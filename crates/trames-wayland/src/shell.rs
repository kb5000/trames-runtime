// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::popup::Positioner;
use crate::scene::*;
use wayland_protocols::xdg::shell::server::{
    xdg_popup, xdg_positioner, xdg_surface, xdg_toplevel, xdg_wm_base,
};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};

pub(crate) fn globals(handle: &DisplayHandle) {
    handle.create_global::<State, xdg_wm_base::XdgWmBase, _>(3, ());
}
impl State {
    pub(crate) fn dismiss_popups(&mut self) {
        let ids = std::mem::take(&mut self.seat.popups);
        for id in ids.into_iter().rev() {
            self.surface_unmapped(id);
            if let Some(s) = self.surfaces.get_mut(&id) {
                if let Some(p) = &s.popup {
                    p.popup_done();
                }
                s.dismissed = true;
                s.current = None;
                s.gpu_pending.clear();
            }
        }
        self.changed();
    }
    pub fn configure(&mut self, id: u64) {
        if let Some(s) = self.surfaces.get(&id) {
            let (w, h) = s.requested_size;
            if w > 0 && h > 0 {
                self.xcommand(id, |xid| crate::xwm::Command::Resize(xid, w, h));
            }
        }
        self.serial = self.serial.wrapping_add(1).max(1);
        let serial = self.serial;
        let Some(s) = self.surfaces.get_mut(&id) else {
            return;
        };
        let mut states = Vec::new();
        if s.mode == WindowMode::Maximized {
            states.extend_from_slice(&(xdg_toplevel::State::Maximized as u32).to_ne_bytes());
        }
        if let Some(top) = &s.top {
            let clamp = |value: u32, min: u32, max: u32| {
                if value == 0 {
                    0
                } else {
                    value
                        .max(min)
                        .min(if max == 0 { 4096 } else { max.max(min) })
                }
            };
            top.configure(
                clamp(s.requested_size.0, s.min_size.0, s.max_size.0) as i32,
                clamp(s.requested_size.1, s.min_size.1, s.max_size.1) as i32,
                states,
            );
        }
        if let Some(popup) = &s.popup {
            let (_, x, y) = s.parent.unwrap_or((0, 0, 0));
            popup.configure(x, y, s.size.0 as i32, s.size.1 as i32);
            if let Some(token) = s.reposition.take() {
                popup.repositioned(token);
            }
        }
        if let Some(xdg) = &s.xdg {
            xdg.configure(serial);
            s.outstanding.push_back(serial);
            s.configured = true;
        }
    }
}
impl GlobalDispatch<xdg_wm_base::XdgWmBase, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<xdg_wm_base::XdgWmBase>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(r, ());
    }
}
impl Dispatch<xdg_wm_base::XdgWmBase, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &xdg_wm_base::XdgWmBase,
        request: xdg_wm_base::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_wm_base::Request::Destroy | xdg_wm_base::Request::Pong { .. } => {}
            xdg_wm_base::Request::CreatePositioner { id } => {
                init.init(id, std::sync::Mutex::new(Positioner::default()));
            }
            xdg_wm_base::Request::GetXdgSurface { id, surface } => {
                let Some(key) = surface.data::<SurfaceKey>().copied() else {
                    init.post_error(id, 0u32, "foreign surface");
                    return;
                };
                let Some(s) = state.surfaces.get_mut(&key.0) else {
                    return;
                };
                if !matches!(s.role, Role::None | Role::Top | Role::Popup)
                    || s.xdg.is_some()
                    || s.parent.is_some()
                    || s.current.is_some()
                {
                    init.post_error(id, 0u32, "surface already has a role or buffer");
                    return;
                }
                s.xdg = Some(init.init(id, key));
            }
            _ => r.post_error(0u32, "unsupported shell request"),
        }
    }
}
impl Dispatch<xdg_surface::XdgSurface, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &xdg_surface::XdgSurface,
        request: xdg_surface::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_surface::Request::Destroy => {
                if let Some(s) = state.surfaces.get_mut(&key.0) {
                    if s.top.as_ref().is_some_and(Resource::is_alive)
                        || s.popup.as_ref().is_some_and(Resource::is_alive)
                    {
                        r.post_error(6u32, "role must be destroyed before xdg_surface");
                        return;
                    }
                    s.xdg = None;
                    s.configured = false;
                    s.acknowledged = false;
                }
            }
            xdg_surface::Request::GetToplevel { id } => {
                let Some(s) = state.surfaces.get_mut(&key.0) else {
                    return;
                };
                if !matches!(s.role, Role::None | Role::Top) || s.top.is_some() || s.popup.is_some()
                {
                    init.post_error(id, 2u32, "surface already constructed");
                    return;
                }
                s.role = Role::Top;
                s.top = Some(init.init(id, *key));
                state.changed();
            }
            xdg_surface::Request::AckConfigure { serial } => {
                let Some(s) = state.surfaces.get_mut(&key.0) else {
                    return;
                };
                let Some(position) = s.outstanding.iter().position(|v| *v == serial) else {
                    r.post_error(4u32, "unknown configure serial");
                    return;
                };
                s.outstanding.drain(..=position);
                s.acknowledged = true;
                state.changed();
            }
            xdg_surface::Request::SetWindowGeometry {
                x,
                y,
                width,
                height,
            } => {
                if width <= 0 || height <= 0 {
                    r.post_error(5u32, "invalid window geometry");
                    return;
                }
                if let Some(s) = state.surfaces.get_mut(&key.0) {
                    s.pending_geometry = Some((x, y, width as u32, height as u32));
                }
            }
            xdg_surface::Request::GetPopup {
                id,
                parent,
                positioner,
            } => {
                let Some(parent) = parent.and_then(|p| p.data::<SurfaceKey>().copied()) else {
                    init.post_error(id, 3u32, "popup needs a parent");
                    return;
                };
                let Some(pos) = positioner
                    .data::<std::sync::Mutex<Positioner>>()
                    .and_then(|p| p.lock().ok())
                    .map(|p| *p)
                else {
                    return;
                };
                if !pos.complete() {
                    init.post_error(id, 5u32, "incomplete popup positioner");
                    return;
                }
                if !state.surfaces.contains_key(&parent.0) || state.is_descendant(parent.0, key.0) {
                    init.post_error(id, 3u32, "invalid popup parent");
                    return;
                }
                let Some(s) = state.surfaces.get_mut(&key.0) else {
                    return;
                };
                if !matches!(s.role, Role::None | Role::Popup)
                    || s.top.is_some()
                    || s.popup.is_some()
                {
                    init.post_error(id, 2u32, "surface already constructed");
                    return;
                }
                s.role = Role::Popup;
                s.popup = Some(init.init(id, *key));
                let (x, y, w, h) = pos.geometry(state.viewport);
                s.parent = Some((parent.0, x, y));
                s.size = (w, h);
                s.requested_size = s.size;
                state
                    .surfaces
                    .get_mut(&parent.0)
                    .unwrap()
                    .children
                    .push(key.0);
            }
            _ => r.post_error(0u32, "unsupported xdg_surface request"),
        }
    }
}
impl Dispatch<xdg_toplevel::XdgToplevel, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        _: &xdg_toplevel::XdgToplevel,
        request: xdg_toplevel::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let Some(s) = state.surfaces.get_mut(&key.0) else {
            return;
        };
        let mut configure = false;
        match request {
            xdg_toplevel::Request::Destroy => {
                s.top = None;
            }
            xdg_toplevel::Request::SetTitle { title } => {
                s.title = title.chars().take(256).collect()
            }
            xdg_toplevel::Request::SetAppId { app_id } => {
                s.app_id = app_id.chars().take(128).collect()
            }
            xdg_toplevel::Request::SetMaximized | xdg_toplevel::Request::SetFullscreen { .. } => {
                if s.mode == WindowMode::Floating {
                    s.restore_size = s.size;
                }
                s.mode = WindowMode::Maximized;
                s.requested_size = state.viewport;
                configure = true;
            }
            xdg_toplevel::Request::UnsetMaximized | xdg_toplevel::Request::UnsetFullscreen => {
                s.mode = WindowMode::Floating;
                s.requested_size = s.restore_size;
                configure = true;
            }
            xdg_toplevel::Request::SetMinimized => s.mode = WindowMode::Minimized,
            xdg_toplevel::Request::SetParent { parent } => {
                s.top_parent = parent
                    .and_then(|p| p.data::<SurfaceKey>().map(|p| p.0))
                    .filter(|id| *id != key.0);
            }
            xdg_toplevel::Request::SetMinSize { width, height } => {
                if width >= 0 && height >= 0 {
                    s.min_size = (width as u32, height as u32);
                } else if let Some(top) = &s.top {
                    top.post_error(2u32, "negative minimum size");
                }
            }
            xdg_toplevel::Request::SetMaxSize { width, height } => {
                if width >= 0 && height >= 0 {
                    s.max_size = (width as u32, height as u32);
                } else if let Some(top) = &s.top {
                    top.post_error(2u32, "negative maximum size");
                }
            }
            xdg_toplevel::Request::ShowWindowMenu { .. }
            | xdg_toplevel::Request::Move { .. }
            | xdg_toplevel::Request::Resize { .. } => {}
            _ => {}
        }
        if configure {
            state.configure(key.0);
        }
        state.changed();
    }
}
impl Dispatch<xdg_positioner::XdgPositioner, std::sync::Mutex<Positioner>> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        r: &xdg_positioner::XdgPositioner,
        request: xdg_positioner::Request,
        data: &std::sync::Mutex<Positioner>,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let Ok(mut p) = data.lock() else { return };
        match request {
            xdg_positioner::Request::Destroy => {}
            xdg_positioner::Request::SetSize { width, height } => {
                if width <= 0 || height <= 0 {
                    r.post_error(0u32, "invalid popup size");
                } else {
                    p.size = (width, height);
                }
            }
            xdg_positioner::Request::SetAnchorRect {
                x,
                y,
                width,
                height,
            } => {
                if width <= 0 || height <= 0 {
                    r.post_error(0u32, "invalid anchor rectangle");
                } else {
                    p.rect = (x, y, width, height);
                }
            }
            xdg_positioner::Request::SetOffset { x, y } => p.offset = (x, y),
            xdg_positioner::Request::SetAnchor { anchor } => {
                if let wayland_server::WEnum::Value(value) = anchor {
                    p.anchor = value as u32;
                } else {
                    r.post_error(0u32, "invalid anchor");
                }
            }
            xdg_positioner::Request::SetGravity { gravity } => {
                if let wayland_server::WEnum::Value(value) = gravity {
                    p.gravity = value as u32;
                } else {
                    r.post_error(0u32, "invalid gravity");
                }
            }
            xdg_positioner::Request::SetConstraintAdjustment {
                constraint_adjustment,
            } => {
                if let wayland_server::WEnum::Value(value) = constraint_adjustment {
                    p.constraints = value.bits();
                } else {
                    r.post_error(0u32, "invalid constraint adjustment");
                }
            }
            _ => {}
        }
    }
}
impl Dispatch<xdg_popup::XdgPopup, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        _: &xdg_popup::XdgPopup,
        request: xdg_popup::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_popup::Request::Destroy => {
                state.surface_unmapped(key.0);
                if let Some(s) = state.surfaces.get_mut(&key.0) {
                    s.popup = None;
                    s.current = None;
                }
                state.seat.popups.retain(|id| *id != key.0);
                state.changed();
            }
            xdg_popup::Request::Grab { serial, .. } => {
                let parent = state
                    .surfaces
                    .get(&key.0)
                    .and_then(|s| s.parent)
                    .map(|p| p.0);
                // GTK keyboard menus can be opened from key release; pointer
                // menus keep using the button-press implicit grab serial.
                let valid = [state.seat.press_serial, state.seat.key_serial]
                    .into_iter()
                    .flatten()
                    .any(|(issued, target)| {
                        issued == serial && parent.is_some_and(|p| state.is_descendant(target, p))
                    })
                    && state
                        .seat
                        .popups
                        .last()
                        .is_none_or(|id| Some(*id) == parent)
                    && state
                        .surfaces
                        .get(&key.0)
                        .is_some_and(|s| s.current.is_none() && !s.dismissed)
                    && !state.seat.popups.contains(&key.0);
                if !valid {
                    if let Some(p) = state.surfaces.get(&key.0).and_then(|s| s.popup.as_ref()) {
                        p.post_error(0u32, "invalid popup implicit-grab serial or parent");
                    }
                    return;
                }
                state.seat.popups.push(key.0);
            }
            xdg_popup::Request::Reposition { positioner, token } => {
                let Some(p) = positioner
                    .data::<std::sync::Mutex<Positioner>>()
                    .and_then(|p| p.lock().ok())
                    .map(|p| *p)
                else {
                    return;
                };
                if !p.complete() {
                    return;
                }
                let (x, y, w, h) = p.geometry(state.viewport);
                if let Some(s) = state.surfaces.get_mut(&key.0) {
                    if let Some((parent, ..)) = s.parent {
                        s.parent = Some((parent, x, y));
                    }
                    s.size = (w, h);
                    s.requested_size = s.size;
                    s.reposition = Some(token);
                }
                state.configure(key.0);
                state.changed();
            }
            _ => {}
        }
    }
}
