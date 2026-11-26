// SPDX-License-Identifier: GPL-3.0-or-later
//! One native seat. UI sends evdev keycodes and logical surface coordinates;
//! all protocol resources remain on the compositor thread.
use super::*;
use crate::scene::SurfaceKey;
use std::{collections::BTreeSet, os::fd::AsFd};
use wayland_server::protocol::{wl_keyboard, wl_pointer, wl_seat, wl_touch};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};

/// Native XKB masks refer to the accompanying host keymap, including layout group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyboardModifiers {
    pub depressed: u32,
    pub latched: u32,
    pub locked: u32,
    pub group: u32,
}
impl KeyboardModifiers {
    pub(crate) fn legacy(modifiers: u32) -> Self {
        Self {
            depressed: modifiers & !2,
            locked: modifiers & 2,
            ..Self::default()
        }
    }
}
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
    /// Physical evdev event; modifier updates arrive separately in protocol order.
    RawKey {
        key: u32,
        pressed: bool,
        time: u32,
    },
    Modifiers(KeyboardModifiers),
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
    keymap: Option<std::sync::Arc<trames_shared::SharedFile>>,
    keymap_bytes: std::sync::Arc<[u8]>,
    native_modifiers: Option<KeyboardModifiers>,
    repeat: Option<(i32, i32)>,
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
    fn interaction_allowed(&self, window: u64, serial: u32) -> bool {
        !self.seat.buttons.is_empty()
            && self.seat.press_serial.is_some_and(|(token, surface)| {
                token == serial && self.is_descendant(surface, window)
            })
    }
    pub(crate) fn request_interaction(&mut self, window: u64, serial: u32, edges: u32) {
        if !self.interaction_allowed(window, serial) {
            return;
        }
        if let Some(surface) = self.surfaces.get_mut(&window).filter(|s| s.is_toplevel()) {
            surface.interaction = Some(crate::WindowInteraction { serial, edges });
            self.changed();
        }
    }
    /// Native clipboard reads can wait on an OS permission dialog which owns
    /// physical key-up delivery. End the gesture before handing off to UIKit;
    /// keep selection/text focus so the pending transfer still belongs here.
    pub(crate) fn cancel_held_keys(&mut self) {
        let keys = self.seat.pressed.iter().copied().collect::<Vec<_>>();
        if let Some(mut m) = self.seat.native_modifiers {
            for key in keys {
                self.input(InputEvent::RawKey {
                    key,
                    pressed: false,
                    time: 0,
                });
            }
            m.depressed = 0;
            m.latched = 0;
            self.input(InputEvent::Modifiers(m));
            return;
        }
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
        self.seat.keymap_bytes = bytes.into();
        self.seat.keymap = Some(std::sync::Arc::new(map));
        Ok(())
    }
    pub(crate) fn keyboard_map(
        &mut self,
        map: std::sync::Arc<trames_shared::SharedFile>,
        bytes: std::sync::Arc<[u8]>,
    ) {
        self.seat
            .native_modifiers
            .get_or_insert_with(KeyboardModifiers::default);
        if bytes == self.seat.keymap_bytes {
            return;
        }
        self.seat.keymap = Some(map);
        self.seat.keymap_bytes = bytes;
        self.seat.keyboards.retain(Resource::is_alive);
        let serial = self.next_serial();
        let modifiers = self
            .seat
            .native_modifiers
            .unwrap_or_else(|| KeyboardModifiers::legacy(self.seat.modifiers));
        for keyboard in &self.seat.keyboards {
            if let Ok(fd) = self.seat.keymap.as_ref().unwrap().duplicate_fd() {
                keyboard.keymap(
                    wl_keyboard::KeymapFormat::XkbV1,
                    fd.as_fd(),
                    self.seat.keymap_bytes.len() as u32,
                );
                if self
                    .seat
                    .focus
                    .and_then(|id| self.surfaces.get(&id))
                    .is_some_and(|s| s.x11.is_none() && connection(keyboard) == s.connection)
                {
                    keyboard.modifiers(
                        serial,
                        modifiers.depressed,
                        modifiers.latched,
                        modifiers.locked,
                        modifiers.group,
                    );
                }
            }
        }
    }
    pub(crate) fn keyboard_repeat(&mut self, rate: i32, delay: i32) {
        self.seat.repeat = Some((rate, delay));
        self.seat.keyboards.retain(Resource::is_alive);
        for k in &self.seat.keyboards {
            if k.version() >= 4 {
                k.repeat_info(rate, delay);
            }
        }
    }
    fn modifiers(&mut self, m: KeyboardModifiers) {
        self.seat.modifiers = m.depressed | m.latched | m.locked;
        self.seat.native_modifiers = Some(m);
        if let Some(id) = self
            .seat
            .focus
            .filter(|id| self.surfaces.get(id).is_some_and(|s| s.x11.is_some()))
        {
            self.xcommand(id, |_| crate::xwm::Command::Modifiers(m));
            return;
        }
        let serial = self.next_serial();
        if let Some(s) = self.seat.focus.and_then(|id| self.surfaces.get(&id)) {
            for k in &self.seat.keyboards {
                if k.is_alive()
                    && connection(k) == s.connection
                    && (s.x11.is_none() || self.seat.native_modifiers.is_none())
                {
                    k.modifiers(serial, m.depressed, m.latched, m.locked, m.group);
                }
            }
        }
    }
    fn raw_key(&mut self, key: u32, pressed: bool, time: u32) {
        if key > 767 {
            return;
        }
        let changed = if pressed {
            self.seat.pressed.insert(key)
        } else {
            self.seat.pressed.remove(&key)
        };
        if !changed {
            return;
        }
        let serial = self.next_serial();
        if let Some(id) = self.seat.focus {
            self.seat.key_serial = Some((serial, id));
            if pressed {
                self.seat.press_serial = Some((serial, id));
            }
        }
        if self.xraw_key(key, pressed) {
            return;
        }
        if let Some(s) = self.seat.focus.and_then(|id| self.surfaces.get(&id)) {
            for k in &self.seat.keyboards {
                if connection(k) == s.connection {
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
    pub(crate) fn focus_toplevel(&self, mut id: Option<u64>) -> Option<u64> {
        for _ in 0..256 {
            let surface = self.surfaces.get(&id?)?;
            if surface.is_toplevel() {
                return id;
            }
            id = surface.parent.map(|parent| parent.0);
        }
        None
    }
    pub(crate) fn focus_surface(&mut self, id: Option<u64>) {
        let id = id.filter(|id| self.surfaces.get(id).is_some_and(|s| s.current.is_some()));
        if self.seat.focus == id {
            return;
        }
        let previous_top = self.focus_toplevel(self.seat.focus);
        let next_top = self.focus_toplevel(id);
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
        if let Some(m) = &mut self.seat.native_modifiers {
            m.depressed = 0;
            m.latched = 0;
        }
        if let Some(s) = id.and_then(|id| self.surfaces.get(&id)) {
            for k in &self.seat.keyboards {
                if k.is_alive() && connection(k) == s.connection {
                    k.enter(serial, &s.resource, Vec::new());
                    let m = self.seat.native_modifiers.unwrap_or_default();
                    if s.x11.is_none() || self.seat.native_modifiers.is_none() {
                        k.modifiers(serial, m.depressed, m.latched, m.locked, m.group);
                    }
                }
            }
        }
        self.text_focus_enter();
        self.selection_focus_changed();
        if previous_top != next_top {
            for top in [previous_top, next_top].into_iter().flatten() {
                self.configure(top);
            }
        }
        self.changed();
    }
    fn focus_pointer_window(&mut self) {
        // Pointer delivery and keyboard activation are different. Non-grabbing
        // popups (Firefox panels) retain their parent's keyboard focus; sending
        // a leave on that parent makes GTK roll them up before mouse release.
        let focus = self.seat.pointer.and_then(|pointer| {
            self.seat
                .popups
                .iter()
                .rev()
                .find(|&&popup| self.is_descendant(pointer, popup))
                .copied()
                .or_else(|| self.focus_toplevel(Some(pointer)))
        });
        self.focus_surface(focus);
    }
    pub(crate) fn input(&mut self, event: InputEvent) {
        if self.defer_xkey(&event) {
            return;
        }
        self.seat.keyboards.retain(Resource::is_alive);
        self.seat.pointers.retain(Resource::is_alive);
        match event {
            InputEvent::Focus { window } => {
                // Native focus names the containing toplevel, including when
                // its popup overlay becomes key or a button is released. That
                // is not a focus departure: retain the popup's keyboard focus,
                // implicit grab and complete click instead of dismissing it.
                if window.is_some() && self.focus_toplevel(self.seat.focus) == window {
                    return;
                }
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
                        self.focus_pointer_window();
                        return;
                    }
                    if !self.seat.buttons.insert(button) {
                        return;
                    }
                    if self.seat.buttons.len() == 1 {
                        self.seat.grab = self.seat.pointer;
                    }
                    self.focus_pointer_window();
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
            InputEvent::RawKey { key, pressed, time } => self.raw_key(key, pressed, time),
            InputEvent::Modifiers(m) => self.modifiers(m),
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
                self.seat.native_modifiers = None;
                self.seat.modifiers = modifiers;
                let serial = self.next_serial();
                if let Some(id) = self.seat.focus {
                    self.seat.key_serial = Some((serial, id));
                    if pressed {
                        self.seat.press_serial = Some((serial, id));
                    }
                }
                if self.xkey(key, pressed, modifiers) {
                    return;
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
            let (width, height) = image.destination;
            if lx >= 0.0
                && ly >= 0.0
                && lx < f64::from(width)
                && ly < f64::from(height)
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
                    let (rate, delay) = state.seat.repeat.unwrap_or((25, 600));
                    k.repeat_info(rate, delay);
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
                        let m = state
                            .seat
                            .native_modifiers
                            .unwrap_or_else(|| KeyboardModifiers::legacy(state.seat.modifiers));
                        if s.x11.is_none() || state.seat.native_modifiers.is_none() {
                            k.modifiers(state.serial, m.depressed, m.latched, m.locked, m.group);
                        }
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
    use wayland_protocols::xdg::shell::server::{xdg_popup, xdg_toplevel};
    use wayland_server::protocol::{wl_buffer, wl_surface};

    #[test]
    fn native_interactions_require_a_live_press_in_the_same_window() {
        let mut state = State::default();
        state.seat.press_serial = Some((7, 42));
        assert!(!state.interaction_allowed(42, 7));
        state.seat.buttons.insert(0x110);
        assert!(state.interaction_allowed(42, 7));
        assert!(!state.interaction_allowed(41, 7));
        assert!(!state.interaction_allowed(42, 8));
        state.seat.buttons.clear();
        assert!(!state.interaction_allowed(42, 7));
    }
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

    fn popup_scene() -> Compositor {
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
            if parent.is_none() {
                surface.top = Some(
                    client
                        .create_resource::<xdg_toplevel::XdgToplevel, _, State>(
                            &handle,
                            3,
                            SurfaceKey(id),
                        )
                        .unwrap(),
                );
            } else {
                surface.popup = Some(
                    client
                        .create_resource::<xdg_popup::XdgPopup, _, State>(
                            &handle,
                            3,
                            SurfaceKey(id),
                        )
                        .unwrap(),
                );
            }
            surface.current = Some(image.clone());
            compositor.state.surfaces.insert(id, surface);
        }
        compositor
    }

    #[test]
    fn popup_workspace_is_relative_to_the_current_parent_geometry() {
        let mut compositor = popup_scene();
        let state = &mut compositor.state;
        state.surfaces.get_mut(&1).unwrap().geometry = Some((10, 10, 1920, 928));
        assert_eq!(state.popup_constraint_bounds(1), (0, 0, 1920, 928));
        state.surfaces.get_mut(&1).unwrap().popup_bounds = Some((-200, -100, 1920, 1020));
        state.surfaces.get_mut(&2).unwrap().parent = Some((1, 400, 50));
        state.surfaces.get_mut(&3).unwrap().parent = Some((2, 20, 10));
        assert_eq!(state.popup_constraint_bounds(1), (-200, -100, 1920, 1020));
        assert_eq!(state.popup_constraint_bounds(2), (-600, -150, 1920, 1020));
        assert_eq!(state.popup_constraint_bounds(3), (-620, -160, 1920, 1020));
    }
    #[test]
    fn non_grabbing_popup_click_keeps_the_parent_keyboard_focus() {
        let mut compositor = popup_scene();
        let state = &mut compositor.state;
        state.focus_surface(Some(1));
        state.seat.pointer = Some(3);
        state.seat.pressed.insert(29);
        state.seat.modifiers = 4;
        // Firefox's hamburger menu does not request xdg_popup.grab. A keyboard
        // leave on its main surface rolls the menu up during the mouse press.
        state.input(InputEvent::Button {
            button: 0x110,
            pressed: true,
            time: 1,
        });
        assert_eq!(state.seat.focus, Some(1));
        assert_eq!(state.seat.grab, Some(3));
        assert!(state.seat.pressed.contains(&29));
        assert_eq!(state.seat.modifiers, 4);
        state.input(InputEvent::Focus { window: Some(1) });
        state.input(InputEvent::Button {
            button: 0x110,
            pressed: false,
            time: 2,
        });
        assert_eq!(state.seat.focus, Some(1));
        assert!(state.seat.buttons.is_empty());
        assert!(state.surfaces[&3].current.is_some());
    }
    #[test]
    fn native_refocus_preserves_nested_popup_clicks_and_keyboard_state() {
        let mut compositor = popup_scene();
        let state = &mut compositor.state;
        state.focus_surface(Some(3));
        state.seat.pointer = Some(3);
        state.seat.popups = vec![2, 3];
        state.seat.pressed.insert(29);
        state.seat.modifiers = 4;
        let serial = state.serial;
        // AppKit reports the containing toplevel for both an overlay becoming
        // key and each mouse button. Neither is a departure from its popup tree.
        state.input(InputEvent::Focus { window: Some(1) });
        assert_eq!(state.seat.focus, Some(3));
        assert_eq!(state.seat.popups, [2, 3]);
        assert!(state.surfaces[&2].current.is_some());
        assert!(state.surfaces[&3].current.is_some());
        assert!(state.seat.pressed.contains(&29));
        assert_eq!(state.seat.modifiers, 4);
        assert_eq!(state.serial, serial);
        state.input(InputEvent::Button {
            button: 0x110,
            pressed: true,
            time: 1,
        });
        state.input(InputEvent::Focus { window: Some(1) });
        state.input(InputEvent::Button {
            button: 0x110,
            pressed: false,
            time: 2,
        });
        assert_eq!(state.seat.focus, Some(3));
        assert_eq!(state.seat.popups, [2, 3]);
        assert!(state.seat.buttons.is_empty());
        // A real toplevel change must still dismiss menus and release keys.
        state.input(InputEvent::Focus { window: Some(4) });
        assert_eq!(state.seat.focus, Some(4));
        assert!(state.seat.popups.is_empty());
        assert!(state.surfaces[&2].current.is_none());
        assert!(state.surfaces[&3].current.is_none());
        assert!(state.seat.pressed.is_empty());
        state.input(InputEvent::Button {
            button: 0x110,
            pressed: true,
            time: 3,
        });
        state.input(InputEvent::Focus { window: None });
        assert_eq!(state.seat.focus, None);
        assert!(state.seat.buttons.is_empty());
        assert_eq!(state.seat.grab, None);
    }

    #[test]
    fn nested_popup_unmap_restores_mapped_ancestors_without_stealing_other_focus() {
        let mut compositor = popup_scene();
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

#[cfg(test)]
mod native_keyboard_tests {
    use super::*;
    #[test]
    fn native_permission_handoff_releases_physical_keys_and_retains_group_and_locks() {
        let mut state = State::default();
        state.input(InputEvent::Modifiers(KeyboardModifiers {
            depressed: 129,
            latched: 4,
            locked: 16,
            group: 1,
        }));
        for key in [42, 100, 16] {
            state.input(InputEvent::RawKey {
                key,
                pressed: true,
                time: 0,
            });
        }
        state.cancel_held_keys();
        assert!(state.seat.pressed.is_empty());
        assert_eq!(
            state.seat.native_modifiers,
            Some(KeyboardModifiers {
                depressed: 0,
                latched: 0,
                locked: 16,
                group: 1
            })
        );
    }
    #[test]
    fn duplicate_host_repeat_does_not_create_a_second_physical_press() {
        let mut state = State::default();
        state.input(InputEvent::RawKey {
            key: 30,
            pressed: true,
            time: 1,
        });
        let serial = state.serial;
        state.input(InputEvent::RawKey {
            key: 30,
            pressed: true,
            time: 2,
        });
        assert_eq!(state.serial, serial);
        state.input(InputEvent::RawKey {
            key: 30,
            pressed: false,
            time: 3,
        });
        assert!(state.seat.pressed.is_empty());
        assert_ne!(state.serial, serial);
    }
}
