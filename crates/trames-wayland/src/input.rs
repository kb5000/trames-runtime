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
        self.changed();
    }
    pub(crate) fn input(&mut self, event: InputEvent) {
        self.seat.keyboards.retain(Resource::is_alive);
        self.seat.pointers.retain(Resource::is_alive);
        match event {
            InputEvent::Focus { window } => self.focus_surface(window),
            InputEvent::Pointer { window, x, y, time } => {
                if !x.is_finite() || !y.is_finite() {
                    return;
                }
                let hit = self.windows_hit(window, x, y);
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
                    self.focus_surface(self.seat.pointer);
                }
                let serial = self.next_serial();
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
                if let Some(s) = self.seat.focus.and_then(|id| self.surfaces.get(&id)) {
                    for k in &self.seat.keyboards {
                        if connection(k) == s.connection {
                            k.modifiers(serial, modifiers, 0, 0, 0);
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
            if lx >= 0.0
                && ly >= 0.0
                && lx < f64::from(image.buffer.pixels.width) / f64::from(image.scale)
                && ly < f64::from(image.buffer.pixels.height) / f64::from(image.scale)
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
                        k.modifiers(state.serial, state.seat.modifiers, 0, 0, 0);
                    }
                }
                state.seat.keyboards.push(k);
            }
            wl_seat::Request::GetPointer { id } => {
                let p = init.init(id, ());
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
                if s.top.is_some() || s.parent.is_some() || s.xdg.is_some() {
                    r.post_error(0u32, "cursor surface already has a role");
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
