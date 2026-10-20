// SPDX-License-Identifier: GPL-3.0-or-later
//! One native seat. UI sends evdev keycodes and logical surface coordinates;
//! all protocol resources remain on the compositor thread.
use super::*;
use crate::scene::SurfaceKey;
use std::{collections::BTreeSet, os::fd::AsFd};
use wayland_server::protocol::{wl_keyboard, wl_pointer, wl_seat, wl_touch};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};

#[derive(Clone, Debug)]
pub enum InputEvent {
    Focus {
        window: Option<u64>,
    },
    Pointer {
        window: u64,
        x: f64,
        y: f64,
        time: u32,
    },
    Button {
        button: u32,
        pressed: bool,
        time: u32,
    },
    Scroll {
        horizontal: f64,
        vertical: f64,
        time: u32,
    },
    Key {
        key: u32,
        pressed: bool,
        modifiers: u32,
        time: u32,
    },
}
#[derive(Default)]
pub(crate) struct Seat {
    pub keyboards: Vec<wl_keyboard::WlKeyboard>,
    pointers: Vec<wl_pointer::WlPointer>,
    pub focus: Option<u64>,
    pointer: Option<u64>,
    pointer_position: (f64, f64),
    buttons: BTreeSet<u32>,
    grab: Option<u64>,
    pub popups: Vec<u64>,
    pub press_serial: Option<(u32, u64)>,
    pub key_serial: Option<(u32, u64)>,
    pressed: BTreeSet<u32>,
    modifiers: u32,
    keymap: Option<trames_shared::SharedFile>,
}
fn connection<R: Resource>(resource: &R) -> u64 {
    resource
        .client()
        .and_then(|c| c.get_data::<ClientIdentity>().map(|i| i.connection))
        .unwrap_or(0)
}
pub(crate) fn globals(handle: &DisplayHandle) {
    handle.create_global::<State, wl_seat::WlSeat, _>(7, ());
}
impl State {
    /// Native clipboard reads can wait on an OS permission dialog which owns
    /// physical key-up delivery. End the gesture before handing off to UIKit;
    /// keep selection/text focus so the pending transfer still belongs here.
    pub(crate) fn cancel_held_keys(&mut self) {
        let keys = self.seat.pressed.iter().copied().collect::<Vec<_>>();
        let modifiers = self.seat.modifiers & 2; // Preserve Caps Lock.
        for key in keys {
            self.input(InputEvent::Key {
                key,
                pressed: false,
                modifiers,
                time: 0,
            });
        }
    }
    /// A menu can unmap before its activation sends set_selection. Restore the
    /// nearest mapped parent while the old resource still exists, so keyboard,
    /// text-input and data-device focus leave the popup together.
    pub(crate) fn surface_unmapped(&mut self, id: u64) {
        if self
            .seat
            .focus
            .is_some_and(|focus| self.is_descendant(focus, id))
        {
            let mut parent = self.surfaces.get(&id).and_then(|s| s.parent).map(|p| p.0);
            for _ in 0..256 {
                let Some(surface) = parent.and_then(|p| self.surfaces.get(&p)) else {
                    parent = None;
                    break;
                };
                if surface.current.is_some() && !surface.dismissed && surface.resource.is_alive() {
                    break;
                }
                parent = surface.parent.map(|p| p.0);
            }
            self.focus_surface(parent);
        }
        if self
            .seat
            .pointer
            .is_some_and(|pointer| self.is_descendant(pointer, id))
        {
            let serial = self.next_serial();
            if let Some(surface) = self.seat.pointer.and_then(|p| self.surfaces.get(&p)) {
                for pointer in &self.seat.pointers {
                    if pointer.is_alive() && connection(pointer) == surface.connection {
                        pointer.leave(serial, &surface.resource);
                        if pointer.version() >= 5 {
                            pointer.frame();
                        }
                    }
                }
            }
            self.seat.pointer = None;
        }
        if self
            .seat
            .grab
            .is_some_and(|grab| self.is_descendant(grab, id))
        {
            self.seat.grab = None;
        }
    }
    pub(crate) fn next_serial(&mut self) -> u32 {
        self.serial = self.serial.wrapping_add(1).max(1);
        self.serial
    }
    pub(crate) fn initialize_input(&mut self) -> io::Result<()> {
        let map = trames_shared::SharedFile::anonymous()?;
        let mut bytes = include_bytes!("../data/us.xkb").to_vec();
        bytes.push(0);
        map.write_at(0, &bytes)?;
        self.seat.keymap = Some(map);
        Ok(())
    }
    pub(crate) fn focus_surface(&mut self, id: Option<u64>) {
        let id = id.filter(|id| self.surfaces.get(id).is_some_and(|s| s.current.is_some()));
        if self.seat.focus == id {
            return;
        }
        let serial = self.next_serial();
        if let Some(old) = self.seat.focus.and_then(|id| self.surfaces.get(&id)) {
            for k in &self.seat.keyboards {
                if k.is_alive() && connection(k) == old.connection {
                    k.leave(serial, &old.resource);
                }
            }
        }
        self.text_focus_leave();
        self.seat.focus = id;
        self.xfocus(id);
        // Losing native focus cancels held keys rather than leaving a guest
        // modifier stuck after switching to the terminal or another window.
        self.seat.pressed.clear();
        self.seat.modifiers = 0;
        if let Some(s) = id.and_then(|id| self.surfaces.get(&id)) {
            for k in &self.seat.keyboards {
                if k.is_alive() && connection(k) == s.connection {
                    k.enter(serial, &s.resource, Vec::new());
                    k.modifiers(serial, 0, 0, 0, 0);
                }
            }
        }
        self.text_focus_enter();
        self.selection_focus_changed();
        self.changed();
    }
    pub(crate) fn input(&mut self, event: InputEvent) {
        if self.defer_xkey(&event) {
            return;
        }
        self.seat.keyboards.retain(Resource::is_alive);
        self.seat.pointers.retain(Resource::is_alive);
        match event {
            InputEvent::Focus { window } => {
                self.dismiss_popups();
                if window.is_none() {
                    let buttons = self.seat.buttons.iter().copied().collect::<Vec<_>>();
                    for button in buttons {
                        self.input(InputEvent::Button {
                            button,
                            pressed: false,
                            time: 0,
                        });
                    }
                    self.seat.grab = None;
                }
                self.focus_surface(window);
            }
            InputEvent::Pointer { window, x, y, time } => {
                if !x.is_finite() || !y.is_finite() {
                    return;
                }
                let hit = self
                    .seat
                    .grab
                    .and_then(|id| {
                        let windows = crate::scene::snapshot(&self.surfaces);
                        let image = windows
                            .iter()
                            .flat_map(|w| &w.scene)
                            .find(|i| i.surface == id)?;
                        Some((id, x - f64::from(image.x), y - f64::from(image.y)))
                    })
                    .or_else(|| {
                        if self.seat.buttons.is_empty() {
                            self.windows_hit(window, x, y)
                        } else {
                            None
                        }
                    });
                let serial = self.next_serial();
                let target = hit.map(|(id, _, _)| id);
                if target != self.seat.pointer {
                    if let Some(s) = self.seat.pointer.and_then(|id| self.surfaces.get(&id)) {
                        for p in &self.seat.pointers {
                            if p.is_alive() && connection(p) == s.connection {
                                p.leave(serial, &s.resource);
                                if p.version() >= 5 {
                                    p.frame();
                                }
                            }
                        }
                    }
                    self.seat.pointer = target;
                    if let Some((id, lx, ly)) = hit {
                        let s = &self.surfaces[&id];
                        for p in &self.seat.pointers {
                            if connection(p) == s.connection {
                                p.enter(serial, &s.resource, lx, ly);
                                if p.version() >= 5 {
                                    p.frame();
                                }
                            }
                        }
                    }
                }
                if let Some((id, lx, ly)) = hit {
                    self.seat.pointer_position = (lx, ly);
                    let s = &self.surfaces[&id];
                    for p in &self.seat.pointers {
                        if connection(p) == s.connection {
                            p.motion(time, lx, ly);
                            if p.version() >= 5 {
                                p.frame();
                            }
                        }
                    }
                }
            }
            InputEvent::Button {
                button,
                pressed,
                time,
            } => {
                if !(0x110..=0x117).contains(&button) {
                    return;
                }
                if pressed {
                    if self.seat.popups.last().is_some_and(|&popup| {
                        self.seat
                            .pointer
                            .is_none_or(|target| !self.is_descendant(target, popup))
                    }) {
                        self.dismiss_popups();
                        self.focus_surface(self.seat.pointer);
                        return;
                    }
                    if !self.seat.buttons.insert(button) {
                        return;
                    }
                    if self.seat.buttons.len() == 1 {
                        self.seat.grab = self.seat.pointer;
                    }
                    self.focus_surface(self.seat.pointer);
                } else if !self.seat.buttons.remove(&button) {
                    return;
                }
                if self.seat.buttons.is_empty() {
                    self.seat.grab = None;
                }
                let serial = self.next_serial();
                if let Some(id) = self.seat.pointer {
                    if pressed {
                        self.seat.press_serial = Some((serial, id));
                    }
                }
                if let Some(s) = self.seat.pointer.and_then(|id| self.surfaces.get(&id)) {
                    for p in &self.seat.pointers {
                        if connection(p) == s.connection {
                            p.button(
                                serial,
                                time,
                                button,
                                if pressed {
                                    wl_pointer::ButtonState::Pressed
                                } else {
                                    wl_pointer::ButtonState::Released
                                },
                            );
                            if p.version() >= 5 {
                                p.frame();
                            }
                        }
                    }
                }
            }
            InputEvent::Scroll {
                horizontal,
                vertical,
                time,
            } => {
                if !horizontal.is_finite() || !vertical.is_finite() {
                    return;
                }
                if let Some(s) = self.seat.pointer.and_then(|id| self.surfaces.get(&id)) {
                    for p in &self.seat.pointers {
                        if connection(p) == s.connection {
                            if p.version() >= 5 {
                                p.axis_source(wl_pointer::AxisSource::Continuous);
                            }
                            if horizontal != 0.0 {
                                p.axis(
                                    time,
                                    wl_pointer::Axis::HorizontalScroll,
                                    horizontal.clamp(-4096.0, 4096.0),
                                );
                            }
                            if vertical != 0.0 {
                                p.axis(
                                    time,
                                    wl_pointer::Axis::VerticalScroll,
                                    vertical.clamp(-4096.0, 4096.0),
                                );
                            }
                            if p.version() >= 5 {
                                p.frame();
                            }
                        }
                    }
                }
            }
            InputEvent::Key {
                key,
                pressed,
                modifiers,
                time,
            } => {
                if key > 767 {
                    return;
                }
                if pressed {
                    self.seat.pressed.insert(key);
                } else {
                    self.seat.pressed.remove(&key);
                }
                self.seat.modifiers = modifiers;
                let serial = self.next_serial();
                if let Some(id) = self.seat.focus {
                    self.seat.key_serial = Some((serial, id));
                    if pressed {
                        self.seat.press_serial = Some((serial, id));
                    }
                }
                if let Some(s) = self.seat.focus.and_then(|id| self.surfaces.get(&id)) {
                    for k in &self.seat.keyboards {
                        if connection(k) == s.connection {
                            k.modifiers(serial, modifiers & !2, 0, modifiers & 2, 0);
                            k.key(
                                serial,
                                time,
                                key,
                                if pressed {
                                    wl_keyboard::KeyState::Pressed
                                } else {
                                    wl_keyboard::KeyState::Released
                                },
                            );
                        }
                    }
                }
            }
        }
    }
    fn windows_hit(&self, window: u64, x: f64, y: f64) -> Option<(u64, f64, f64)> {
        let windows = crate::scene::snapshot(&self.surfaces);
        let window = windows
            .iter()
            .find(|w| w.id == window && w.mode != WindowMode::Minimized)?;
        for image in window.scene.iter().rev() {
            let (lx, ly) = (x - f64::from(image.x), y - f64::from(image.y));
            let (bw, bh) = image.buffer.dimensions();
            let (width, height) = if image.transform & 1 != 0 {
                (bh, bw)
            } else {
                (bw, bh)
            };
            if lx >= 0.0
                && ly >= 0.0
                && lx < f64::from(width) / f64::from(image.scale)
                && ly < f64::from(height) / f64::from(image.scale)
                && self
                    .surfaces
                    .get(&image.surface)
                    .is_some_and(|s| s.input.as_ref().is_none_or(|r| r.contains(lx, ly)))
            {
                return Some((image.surface, lx, ly));
            }
        }
        None
    }
}
impl GlobalDispatch<wl_seat::WlSeat, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<wl_seat::WlSeat>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        let r = init.init(r, ());
        r.capabilities(wl_seat::Capability::Pointer | wl_seat::Capability::Keyboard);
        if r.version() >= 2 {
            r.name("seat0".into());
        }
    }
}
impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &wl_seat::WlSeat,
        request: wl_seat::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_seat::Request::GetKeyboard { id } => {
                let k = init.init(id, ());
                if let Some(map) = &state.seat.keymap {
                    if let Ok(fd) = map.duplicate_fd() {
                        k.keymap(
                            wl_keyboard::KeymapFormat::XkbV1,
                            fd.as_fd(),
                            map.len() as u32,
                        );
                    }
                }
                if k.version() >= 4 {
                    k.repeat_info(25, 600);
                }
                if let Some(s) = state.seat.focus.and_then(|id| state.surfaces.get(&id)) {
                    if connection(&k) == s.connection {
                        k.enter(
                            state.serial,
                            &s.resource,
                            state
                                .seat
                                .pressed
                                .iter()
                                .flat_map(|v| v.to_ne_bytes())
                                .collect(),
                        );
                        k.modifiers(
                            state.serial,
                            state.seat.modifiers & !2,
                            0,
                            state.seat.modifiers & 2,
                            0,
                        );
                    }
                }
                state.seat.keyboards.push(k);
            }
            wl_seat::Request::GetPointer { id } => {
                let p = init.init(id, ());
                if let Some(s) = state.seat.pointer.and_then(|id| state.surfaces.get(&id)) {
                    if connection(&p) == s.connection {
                        let (x, y) = state.seat.pointer_position;
                        p.enter(state.serial, &s.resource, x, y);
                        if p.version() >= 5 {
                            p.frame();
                        }
                    }
                }
                state.seat.pointers.push(p);
            }
            wl_seat::Request::GetTouch { id } => {
                init.init(id, ());
            }
            wl_seat::Request::Release => {}
            _ => r.post_error(0u32, "unsupported seat request"),
        }
    }
}
impl Dispatch<wl_keyboard::WlKeyboard, ()> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &wl_keyboard::WlKeyboard,
        _: wl_keyboard::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}
impl Dispatch<wl_pointer::WlPointer, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &wl_pointer::WlPointer,
        request: wl_pointer::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let wl_pointer::Request::SetCursor {
            surface: Some(surface),
            ..
        } = request
        {
            if connection(r) != connection(&surface) {
                r.post_error(0u32, "foreign cursor surface");
                return;
            }
            if let Some(s) = surface
                .data::<SurfaceKey>()
                .and_then(|key| state.surfaces.get_mut(&key.0))
            {
                if !matches!(
                    s.role,
                    crate::scene::Role::None | crate::scene::Role::Cursor
                ) || s.top.is_some()
                    || s.parent.is_some()
                    || s.xdg.is_some()
                {
                    r.post_error(0u32, "cursor surface already has a role");
                } else {
                    s.role = crate::scene::Role::Cursor;
                }
            }
        }
    }
}
impl Dispatch<wl_touch::WlTouch, ()> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &wl_touch::WlTouch,
        _: wl_touch::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scene::{BufferData, BufferLease, ImageBuffer, ShmBuffer, Surface, SurfaceKey};
    use std::sync::{Arc, Mutex, Weak};
    use wayland_server::protocol::{wl_buffer, wl_surface};

    #[test]
    fn clipboard_permission_cancels_held_keys_without_repeating_releases() {
        let mut state = State::default();
        for key in [29, 47] {
            state.input(InputEvent::Key {
                key,
                pressed: true,
                modifiers: 6,
                time: 1,
            });
        }
        assert_eq!(state.seat.pressed.len(), 2);
        state.cancel_held_keys();
        assert!(state.seat.pressed.is_empty());
        assert_eq!(state.seat.modifiers, 2);
        let serial = state.serial;
        state.cancel_held_keys();
        assert_eq!(state.serial, serial);
        // A delayed physical release and a fresh gesture are still valid.
        state.input(InputEvent::Key {
            key: 47,
            pressed: false,
            modifiers: 2,
            time: 2,
        });
        state.input(InputEvent::Key {
            key: 47,
            pressed: true,
            modifiers: 6,
            time: 3,
        });
        assert!(state.seat.pressed.contains(&47));
    }

    #[test]
    fn nested_popup_unmap_restores_mapped_ancestors_without_stealing_other_focus() {
        let mut compositor = Compositor::new().unwrap();
        let (_peer, socket) = UnixStream::pair().unwrap();
        compositor
            .connect(
                socket,
                ClientIdentity {
                    connection: 1,
                    pid: 1,
                    uid: 0,
                    gid: 0,
                },
            )
            .unwrap();
        let client = compositor.clients.get(&1).unwrap();
        let handle = compositor.display.handle();
        let file = trames_shared::SharedFile::anonymous().unwrap();
        file.set_len(4).unwrap();
        let pixels = Arc::new(ShmBuffer {
            id: 1,
            mapping: file.map(0, 4).unwrap(),
            file,
            width: 1,
            height: 1,
            stride: 4,
            alpha: false,
        });
        let buffer = client
            .create_resource::<wl_buffer::WlBuffer, _, State>(
                &handle,
                1,
                BufferData {
                    pixels,
                    lease: Mutex::new(Weak::new()),
                },
            )
            .unwrap();
        let image = ImageBuffer::Shm(BufferLease::acquire(buffer).unwrap());
        for (id, parent) in [(1, None), (2, Some(1)), (3, Some(2)), (4, None)] {
            let resource = client
                .create_resource::<wl_surface::WlSurface, _, State>(&handle, 4, SurfaceKey(id))
                .unwrap();
            let mut surface = Surface::new(resource, 1);
            surface.parent = parent.map(|p| (p, 0, 0));
            surface.current = Some(image.clone());
            compositor.state.surfaces.insert(id, surface);
        }
        let state = &mut compositor.state;
        state.focus_surface(Some(3));
        state.seat.pointer = Some(3);
        state.seat.grab = Some(3);
        state.surface_unmapped(3);
        assert_eq!(state.seat.focus, Some(2));
        assert_eq!(state.seat.pointer, None);
        assert_eq!(state.seat.grab, None);
        state.surfaces.get_mut(&3).unwrap().current = None;
        // wl_surface.attach(NULL) also releases popup focus before destruction.
        state.focus_surface(Some(2));
        state.seat.popups.push(2);
        state.surfaces.get_mut(&2).unwrap().pending_buffer = Some(None);
        state.commit(2);
        assert_eq!(state.seat.focus, Some(1));
        state.focus_surface(Some(4));
        state.surface_unmapped(2);
        assert_eq!(state.seat.focus, Some(4));
        state.focus_surface(Some(1));
        state.surface_unmapped(1);
        assert_eq!(state.seat.focus, None);
    }
}
