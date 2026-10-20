// SPDX-License-Identifier: GPL-3.0-or-later
//! Connection-scoped X11/Wayland association, using the standard serial protocol.
use super::*;
use crate::{
    scene::{Role, SurfaceKey},
    xwm::{self, Identity},
};
use std::collections::BTreeMap;
use wayland_protocols::xwayland::shell::v1::server::{
    xwayland_shell_v1 as shell, xwayland_surface_v1 as surface,
};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New};

#[derive(Default)]
pub(crate) struct Xwayland {
    pub authorized: Arc<std::sync::Mutex<std::collections::BTreeSet<Identity>>>,
    pub managers: BTreeMap<Identity, xwm::Manager>,
    pub windows: BTreeMap<(Identity, u32), xwm::Window>,
    last_serial: BTreeMap<Identity, u64>,
    focus_serial: u64,
    pending_focus: Option<PendingFocus>,
    texts: BTreeMap<Identity, xwm::Text>,
    text_epoch: u64,
}
struct PendingFocus {
    owner: Identity,
    xid: u32,
    serial: u64,
    keys: Vec<InputEvent>,
}

fn identity(client: &Client) -> Option<Identity> {
    client
        .get_data::<ClientIdentity>()
        .map(|i| (i.pid, i.uid, i.gid))
}
pub(crate) fn globals(
    handle: &DisplayHandle,
    authorized: Arc<std::sync::Mutex<std::collections::BTreeSet<Identity>>>,
) {
    handle.create_global::<State, shell::XwaylandShellV1, _>(1, authorized);
}
impl State {
    fn xidentity(&self, id: u64) -> Option<Identity> {
        self.surfaces
            .get(&id)?
            .resource
            .client()
            .as_ref()
            .and_then(identity)
    }
    pub(crate) fn xcommand(&self, id: u64, f: impl FnOnce(u32) -> xwm::Command) {
        if let Some((key, xid)) = self.surfaces.get(&id).and_then(|s| s.x11) {
            if let Some(wm) = self.xwayland.managers.get(&key) {
                let _ = wm.commands.try_send(f(xid));
            }
        }
    }
    pub(crate) fn xfocus(&mut self, id: Option<u64>) {
        let focused = id.and_then(|id| self.surfaces.get(&id)).and_then(|s| s.x11);
        self.xwayland.focus_serial = self.xwayland.focus_serial.wrapping_add(1).max(1);
        self.xwayland.text_epoch = self.xwayland.text_epoch.wrapping_add(1).max(1);
        let serial = self.xwayland.focus_serial;
        self.xwayland.pending_focus = focused.map(|(owner, xid)| PendingFocus {
            owner,
            xid,
            serial,
            keys: Vec::new(),
        });
        for (key, wm) in &self.xwayland.managers {
            let _ = wm.commands.try_send(xwm::Command::Focus(
                serial,
                focused.filter(|(k, _)| k == key).map(|(_, id)| id),
            ));
        }
    }
    pub(crate) fn xtext_context(&self) -> Option<TextContext> {
        let surface = self.seat.focus?;
        let (key, xid) = self.surfaces.get(&surface)?.x11?;
        let text = self.xwayland.texts.get(&key)?;
        if text.window != xid {
            return None;
        }
        Some(TextContext {
            version: 4,
            id: surface | (1 << 63),
            epoch: self.xwayland.text_epoch,
            surface,
            window: surface,
            caret: text.caret,
            ..TextContext::default()
        })
    }
    pub(crate) fn xtext_commit(&self, surface: u64, text: String) {
        if let Some((key, _)) = self.surfaces.get(&surface).and_then(|s| s.x11) {
            if let Some(context) = self.xwayland.texts.get(&key) {
                self.xcommand(surface, |_| xwm::Command::Text(context.token, text));
            }
        }
    }
    pub(crate) fn xkey(&self, key: u32, pressed: bool, modifiers: u32) -> bool {
        let Some(surface) = self
            .seat
            .focus
            .filter(|id| self.surfaces.get(id).is_some_and(|s| s.x11.is_some()))
        else {
            return false;
        };
        self.xcommand(surface, |_| xwm::Command::Key(key, pressed, modifiers));
        true
    }
    pub(crate) fn defer_xkey(&mut self, event: &InputEvent) -> bool {
        if !matches!(event, InputEvent::Key { .. }) {
            return false;
        }

        let Some(pending) = self.xwayland.pending_focus.as_mut() else {
            return false;
        };
        if pending.keys.len() < 256 {
            pending.keys.push(event.clone());
        }
        true
    }
    fn xfocus_ready(&mut self, owner: Identity, serial: u64, xid: u32) {
        if !self
            .xwayland
            .pending_focus
            .as_ref()
            .is_some_and(|p| p.owner == owner && p.serial == serial)
        {
            return;
        }
        let pending = self.xwayland.pending_focus.take().unwrap();
        if pending.xid == xid
            && self
                .seat
                .focus
                .and_then(|id| self.surfaces.get(&id))
                .and_then(|s| s.x11)
                == Some((owner, xid))
        {
            for key in pending.keys {
                self.input(key);
            }
        }
    }
    pub(crate) fn xcommit(&mut self, id: u64) {
        let mut changed = false;
        if let Some(s) = self.surfaces.get_mut(&id) {
            if let Some(serial) = s.pending_xserial.take() {
                s.xserial = Some(serial);
                changed = true;
            }
        }
        if changed {
            self.xassociate(id);
        }
    }
    fn xassociate(&mut self, id: u64) {
        let Some(key) = self.xidentity(id) else {
            return;
        };
        let Some(serial) = self.surfaces.get(&id).and_then(|s| s.xserial) else {
            return;
        };
        let Some(w) = self
            .xwayland
            .windows
            .iter()
            .find_map(|((k, _), w)| (*k == key && w.serial == serial).then(|| w.clone()))
        else {
            return;
        };
        // Reassociation after unmap/remap cannot leave the old surface visible.
        let old = self
            .surfaces
            .iter()
            .filter_map(|(&other, s)| (other != id && s.x11 == Some((key, w.id))).then_some(other))
            .collect::<Vec<_>>();
        for old in old {
            self.xunmap(old);
        }
        let parent = w
            .transient
            .and_then(|p| {
                self.surfaces
                    .iter()
                    .find_map(|(&id, s)| (s.x11 == Some((key, p))).then_some(id))
            })
            .or_else(|| {
                w.override_redirect
                    .then_some(self.seat.focus)
                    .flatten()
                    .filter(|p| {
                        self.surfaces
                            .get(p)
                            .and_then(|s| s.x11)
                            .is_some_and(|(owner, _)| owner == key)
                    })
            });
        // X11 properties are untrusted. Neither native window ownership nor
        // the recursive popup scene may acquire self/ancestor cycles.
        let parent = parent.filter(|&root| {
            let mut next = Some(root);
            for _ in 0..256 {
                let Some(p) = next else { return true };
                if p == id {
                    return false;
                }
                next = self
                    .surfaces
                    .get(&p)
                    .and_then(|s| s.parent.map(|p| p.0).or(s.top_parent));
            }
            false
        });
        let s = self.surfaces.get_mut(&id).unwrap();
        s.x11 = Some((key, w.id));
        s.title = w.title;
        s.app_id = w.class;
        s.top_parent = parent;
        s.min_size = w.min;
        s.max_size = w.max;
        s.configured = true;
        s.acknowledged = true;
        // Override-redirect windows (menus/tooltips) stay relative to their X11
        // parent when known. Ordinary transient dialogs remain native windows.
        if w.override_redirect && s.parent.is_none() {
            if let Some(parent) = parent {
                let parent_geometry = self
                    .surfaces
                    .get(&parent)
                    .and_then(|s| s.x11)
                    .and_then(|k| self.xwayland.windows.get(&k))
                    .map(|p| p.geometry)
                    .unwrap_or_default();
                let s = self.surfaces.get_mut(&id).unwrap();
                s.parent = Some((
                    parent,
                    i32::from(w.geometry.0) - i32::from(parent_geometry.0),
                    i32::from(w.geometry.1) - i32::from(parent_geometry.1),
                ));
                self.surfaces.get_mut(&parent).unwrap().children.push(id);
            }
        }
        self.changed();
    }
    fn xunmap(&mut self, id: u64) {
        self.surface_unmapped(id);
        if let Some(s) = self.surfaces.get_mut(&id) {
            s.current = None;
            s.gpu_pending.clear();
            s.x11 = None;
        }
        self.changed();
    }
    pub(crate) fn pump_xwm(&mut self) {
        let mut updates = Vec::new();
        let mut dead = Vec::new();
        for (&key, wm) in &self.xwayland.managers {
            for _ in 0..256 {
                match wm.updates.try_recv() {
                    Ok(u) => updates.push((key, u)),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        dead.push(key);
                        break;
                    }
                }
            }
        }
        for (key, update) in updates {
            match update {
                xwm::Update::Clipboard(text) => self.set_xclipboard(key, text),
                xwm::Update::ReadClipboard(fd) => {
                    if self
                        .seat
                        .focus
                        .and_then(|id| self.surfaces.get(&id))
                        .and_then(|s| s.x11)
                        .is_some_and(|(owner, _)| owner == key)
                    {
                        self.selection_read(fd);
                    }
                }
                xwm::Update::Text(text) => {
                    let previous = self.xwayland.texts.remove(&key);
                    if previous.as_ref().map(|t| (t.token, t.window, t.generation))
                        != text.as_ref().map(|t| (t.token, t.window, t.generation))
                    {
                        self.xwayland.text_epoch = self.xwayland.text_epoch.wrapping_add(1).max(1);
                    }
                    if let Some(t) = text {
                        self.xwayland.texts.insert(key, t);
                    }
                    self.changed();
                }
                xwm::Update::Focus(serial, xid) => self.xfocus_ready(key, serial, xid),
                xwm::Update::Window(w) => {
                    if self.xwayland.windows.get(&(key, w.id)) == Some(&w) {
                        continue;
                    }
                    if self.xwayland.windows.len() >= 256
                        && !self.xwayland.windows.contains_key(&(key, w.id))
                    {
                        continue;
                    }
                    self.xwayland.windows.insert((key, w.id), w);
                    let ids = self
                        .surfaces
                        .iter()
                        .filter_map(|(&id, s)| {
                            (s.xserial.is_some() && self.xidentity(id) == Some(key)).then_some(id)
                        })
                        .collect::<Vec<_>>();
                    for id in ids {
                        self.xassociate(id);
                    }
                }
                xwm::Update::Remove(xid) => {
                    self.xwayland.windows.remove(&(key, xid));
                    let ids = self
                        .surfaces
                        .iter()
                        .filter_map(|(&id, s)| (s.x11 == Some((key, xid))).then_some(id))
                        .collect::<Vec<_>>();
                    for id in ids {
                        self.xunmap(id);
                    }
                }
            }
        }
        for key in dead {
            if let Ok(mut allowed) = self.xwayland.authorized.lock() {
                allowed.remove(&key);
            }
            self.xwayland.managers.remove(&key);
            self.xwayland.texts.remove(&key);
            // X11 selection bytes are already owned, unlike a live Wayland
            // data source. Preserve copied text after its X server exits.
            self.xwayland.windows.retain(|(k, _), _| *k != key);
            self.xwayland.last_serial.remove(&key);
            let ids = self
                .surfaces
                .iter()
                .filter_map(|(&id, s)| s.x11.filter(|(k, _)| *k == key).map(|_| id))
                .collect::<Vec<_>>();
            for id in ids {
                self.xunmap(id);
            }
            // Inherited Wayland sockets must not acquire a later registration
            // if Linux eventually reuses the dead Xwayland PID.
            for (&id, s) in &self.surfaces {
                if self.xidentity(id) == Some(key) {
                    s.resource.post_error(0u32, "Xwayland manager disconnected");
                }
            }
        }
    }
}
type Authorization = Arc<std::sync::Mutex<std::collections::BTreeSet<Identity>>>;
impl GlobalDispatch<shell::XwaylandShellV1, Authorization> for State {
    fn can_view(client: Client, allowed: &Authorization) -> bool {
        identity(&client).is_some_and(|key| allowed.lock().is_ok_and(|a| a.contains(&key)))
    }
    fn bind(
        state: &mut Self,
        _: &DisplayHandle,
        client: &Client,
        r: New<shell::XwaylandShellV1>,
        _: &Authorization,
        init: &mut DataInit<'_, Self>,
    ) {
        if !identity(client).is_some_and(|key| state.xwayland.managers.contains_key(&key)) {
            init.post_error(r, 0u32, "Xwayland launcher registration required");
            return;
        }
        init.init(r, ());
    }
}
impl Dispatch<shell::XwaylandShellV1, ()> for State {
    fn request(
        state: &mut Self,
        client: &Client,
        r: &shell::XwaylandShellV1,
        request: shell::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        if let shell::Request::GetXwaylandSurface { id, surface } = request {
            if surface.client().as_ref() != Some(client) {
                init.post_error(id, 0u32, "foreign surface");
                return;
            }
            let Some(key) = surface.data::<SurfaceKey>().copied() else {
                return;
            };
            let Some(s) = state.surfaces.get_mut(&key.0) else {
                return;
            };
            if s.role != Role::None || s.xdg.is_some() || s.current.is_some() {
                r.post_error(0u32, "surface already has a role");
                return;
            }
            s.role = Role::X11;
            init.init(id, key);
        }
    }
}
impl Dispatch<surface::XwaylandSurfaceV1, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        client: &Client,
        r: &surface::XwaylandSurfaceV1,
        request: surface::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let surface::Request::SetSerial {
            serial_lo,
            serial_hi,
        } = request
        {
            let serial = u64::from(serial_lo) | (u64::from(serial_hi) << 32);
            let Some(owner) = identity(client) else {
                return;
            };
            let Some(s) = state.surfaces.get_mut(&key.0) else {
                return;
            };
            if s.xserial.is_some() || s.pending_xserial.is_some() {
                r.post_error(0u32, "surface already associated");
                return;
            }
            let last = state.xwayland.last_serial.entry(owner).or_default();
            if serial == 0 || serial <= *last {
                r.post_error(1u32, "invalid association serial");
                return;
            }
            *last = serial;
            s.pending_xserial = Some(serial);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scene::Surface;
    use wayland_server::protocol::wl_surface::WlSurface;

    #[test]
    fn committed_serials_are_scoped_to_client_and_remap_retires_old_surface() {
        let mut c = Compositor::new().unwrap();
        let (_peer, socket) = UnixStream::pair().unwrap();
        let owner = (8, 1000, 1000);
        c.connect(
            socket,
            ClientIdentity {
                connection: 1,
                pid: owner.0,
                uid: owner.1,
                gid: owner.2,
            },
        )
        .unwrap();
        let client = &c.clients[&1];
        for id in 1..=2 {
            let resource = client
                .create_resource::<WlSurface, _, State>(&c.display.handle(), 4, SurfaceKey(id))
                .unwrap();
            let mut s = Surface::new(resource, 1);
            s.role = Role::X11;
            c.state.surfaces.insert(id, s);
        }
        let foreign = (9, 1000, 1000);
        c.state.xwayland.windows.insert(
            (foreign, 42),
            xwm::Window {
                id: 42,
                serial: 1,
                ..Default::default()
            },
        );
        c.state.surfaces.get_mut(&1).unwrap().pending_xserial = Some(1);
        assert!(c.state.surfaces[&1].xserial.is_none());
        c.state.xcommit(1);
        assert!(c.state.surfaces[&1].x11.is_none());
        c.state.xwayland.windows.insert(
            (owner, 43),
            xwm::Window {
                id: 43,
                serial: 1,
                title: "first".into(),
                ..Default::default()
            },
        );
        c.state.xassociate(1);
        assert_eq!(c.state.surfaces[&1].x11, Some((owner, 43)));
        assert_eq!(c.state.surfaces[&1].title, "first");
        c.state
            .xwayland
            .windows
            .get_mut(&(owner, 43))
            .unwrap()
            .serial = 2;
        c.state.surfaces.get_mut(&2).unwrap().pending_xserial = Some(2);
        c.state.xcommit(2);
        assert!(c.state.surfaces[&1].x11.is_none());
        assert_eq!(c.state.surfaces[&2].x11, Some((owner, 43)));
        let w = c.state.xwayland.windows.get_mut(&(owner, 43)).unwrap();
        w.transient = Some(43);
        w.override_redirect = true;
        c.state.xassociate(2);
        assert!(c.state.surfaces[&2].parent.is_none());
        assert!(c.state.surfaces[&2].top_parent.is_none());
        c.state.seat.focus = Some(2);
        c.state.xwayland.pending_focus = Some(PendingFocus {
            owner,
            xid: 43,
            serial: 10,
            keys: vec![InputEvent::Key {
                key: 30,
                pressed: true,
                modifiers: 0,
                time: 1,
            }],
        });
        c.state.xfocus_ready(owner, 9, 43); // An earlier A -> B -> A reply.
        assert!(c.state.xwayland.pending_focus.is_some());
        assert!(c.state.seat.key_serial.is_none());
        c.state.xfocus_ready(owner, 10, 43);
        assert!(c.state.xwayland.pending_focus.is_none());
        assert!(c.state.seat.key_serial.is_some_and(|(_, id)| id == 2));
    }

    #[test]
    fn shell_global_requires_live_launcher_credentials() {
        let mut c = Compositor::new().unwrap();
        let (_peer, socket) = UnixStream::pair().unwrap();
        c.connect(
            socket,
            ClientIdentity {
                connection: 1,
                pid: 8,
                uid: 1000,
                gid: 1000,
            },
        )
        .unwrap();
        let client = c.clients[&1].clone();
        let allowed = &c.state.xwayland.authorized;
        let visible = |client| {
            <State as GlobalDispatch<shell::XwaylandShellV1, Authorization>>::can_view(
                client, allowed,
            )
        };
        assert!(!visible(client.clone()));
        allowed.lock().unwrap().insert((8, 0, 0));
        assert!(!visible(client.clone()));
        allowed.lock().unwrap().insert((8, 1000, 1000));
        assert!(visible(client.clone()));
        allowed.lock().unwrap().remove(&(8, 1000, 1000));
        assert!(!visible(client));
    }
}
