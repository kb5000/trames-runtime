// SPDX-License-Identifier: GPL-3.0-or-later
//! Original text-input v1/v3 wire protocols. Native editing offsets are UTF-8
//! bytes; UIKit converts its UTF-16 document positions at the UI boundary.
use super::*;
use std::collections::BTreeMap;
use wayland_protocols::wp::text_input::{
    zv1::server::{zwp_text_input_manager_v1 as m1, zwp_text_input_v1 as t1},
    zv3::server::{zwp_text_input_manager_v3 as m3, zwp_text_input_v3 as t3},
};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};

#[derive(Clone, Debug, Default)]
pub struct TextContext {
    pub version: u32,
    pub id: u64,
    pub epoch: u64,
    pub surface: u64,
    pub window: u64,
    pub serial: u32,
    pub text: String,
    pub cursor: u32,
    pub anchor: u32,
    pub caret: [i32; 4],
    pub hint: u32,
    pub purpose: u32,
}
#[derive(Clone, Debug, Default)]
pub struct TextEdit {
    pub serial: u32,
    pub context: u64,
    pub epoch: u64,
    pub preedit: Option<(String, i32, i32)>,
    pub commit: Option<String>,
    pub delete_before: u32,
    pub delete_after: u32,
}
#[derive(Default, Clone)]
struct TextState {
    text: String,
    cursor: u32,
    anchor: u32,
    caret: [i32; 4],
    hint: u32,
    purpose: u32,
}
enum Protocol {
    V1(t1::ZwpTextInputV1),
    V3(t3::ZwpTextInputV3),
}
struct Object {
    protocol: Protocol,
    connection: u64,
    surface: Option<u64>,
    entered: bool,
    ready: bool,
    enabled: bool,
    pending_enabled: Option<bool>,
    serial: u32,
    epoch: u64,
    state: TextState,
    pending: TextState,
}
#[derive(Default)]
pub(crate) struct TextInputs {
    objects: BTreeMap<u64, Object>,
    epoch: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct TextKey(u64);
pub(crate) fn globals(h: &DisplayHandle) {
    h.create_global::<State, m1::ZwpTextInputManagerV1, _>(1, ());
    h.create_global::<State, m3::ZwpTextInputManagerV3, _>(1, ());
}
impl State {
    pub(crate) fn text_focus_leave(&mut self) {
        for o in self.text.objects.values_mut() {
            if o.entered {
                match &o.protocol {
                    Protocol::V1(r) => {
                        if r.is_alive() {
                            r.leave();
                        }
                    }
                    Protocol::V3(r) => {
                        if r.is_alive() {
                            if let Some(s) = o.surface.and_then(|id| self.surfaces.get(&id)) {
                                r.leave(&s.resource);
                            }
                        }
                    }
                }
                o.entered = false;
                o.ready = false;
                o.enabled = false;
                o.pending_enabled = None;
            }
        }
    }
    pub(crate) fn text_focus_enter(&mut self) {
        let Some((id, s)) = self
            .seat
            .focus
            .and_then(|id| self.surfaces.get(&id).map(|s| (id, s)))
        else {
            return;
        };
        self.text.epoch = self.text.epoch.wrapping_add(1);
        for o in self.text.objects.values_mut() {
            if o.connection != s.connection {
                continue;
            }
            match &o.protocol {
                Protocol::V3(r) if r.is_alive() => {
                    o.surface = Some(id);
                    o.entered = true;
                    o.epoch = self.text.epoch;
                    r.enter(&s.resource);
                }
                Protocol::V1(r) if r.is_alive() && o.enabled && o.surface == Some(id) => {
                    o.entered = true;
                    o.epoch = self.text.epoch;
                    r.enter(&s.resource);
                }
                _ => {}
            }
        }
    }
    pub(crate) fn text_context(&self) -> Option<TextContext> {
        let (&id, o) = self
            .text
            .objects
            .iter()
            .rev()
            .find(|(_, o)| o.entered && o.ready && o.enabled && o.surface == self.seat.focus)?;
        let surface = o.surface?;
        let mut window = surface;
        for _ in 0..256 {
            let s = self.surfaces.get(&window)?;
            if let Some((p, ..)) = s.parent {
                window = p;
            } else {
                break;
            }
        }
        let mut caret = o.state.caret;
        if let Some(origin) = crate::scene::snapshot(&self.surfaces)
            .iter()
            .find(|w| w.id == window)
            .and_then(|w| {
                w.scene
                    .iter()
                    .find(|s| s.surface == surface)
                    .map(|s| (s.x, s.y))
            })
        {
            caret[0] = caret[0].saturating_add(origin.0);
            caret[1] = caret[1].saturating_add(origin.1);
        }
        Some(TextContext {
            version: match o.protocol {
                Protocol::V1(_) => 1,
                Protocol::V3(_) => 3,
            },
            id,
            epoch: o.epoch,
            surface,
            window,
            serial: o.serial,
            text: o.state.text.clone(),
            cursor: o.state.cursor,
            anchor: o.state.anchor,
            caret,
            hint: o.state.hint,
            purpose: o.state.purpose,
        })
    }
    pub(crate) fn text_edit(&mut self, edit: TextEdit) {
        let Some(context) = self.text_context() else {
            return;
        };
        if context.id != edit.context || context.epoch != edit.epoch {
            return;
        }
        let Some(o) = self.text.objects.get(&edit.context) else {
            return;
        };
        if edit
            .commit
            .as_ref()
            .is_some_and(|s| s.len() > 4096 || s.contains('\0'))
        {
            return;
        }
        // Delete lengths refer to UIKit's current local document, which can
        // include previous input events not yet acknowledged by the client.
        // Rechecking against an older surrounding-text snapshot drops legitimate
        // rapid edits. Preserve the originating client serial on the wire; the
        // client applies its own reset/serial rules, as on a native compositor.
        if edit.delete_before > 4096 || edit.delete_after > 4096 {
            return;
        }
        if let Some((s, start, end)) = &edit.preedit {
            if s.len() > 4096 || s.contains('\0') {
                return;
            }
            if [*start, *end]
                .iter()
                .any(|&p| p < -1 || p >= 0 && !s.is_char_boundary(p as usize))
            {
                return;
            }
        }
        match &o.protocol {
            Protocol::V3(r) => {
                if edit.delete_before != 0 || edit.delete_after != 0 {
                    r.delete_surrounding_text(edit.delete_before, edit.delete_after);
                }
                if let Some(s) = edit.commit {
                    r.commit_string(Some(s));
                }
                if let Some((s, start, end)) = edit.preedit {
                    r.preedit_string(Some(s), start, end);
                }
                r.done(edit.serial);
            }
            Protocol::V1(r) => {
                if edit.delete_before != 0 || edit.delete_after != 0 {
                    r.delete_surrounding_text(
                        -(edit.delete_before as i32),
                        edit.delete_before + edit.delete_after,
                    );
                }
                if let Some((s, start, _)) = edit.preedit {
                    r.preedit_cursor(start);
                    r.preedit_string(edit.serial, s, String::new());
                }
                if let Some(s) = edit.commit {
                    r.commit_string(edit.serial, s);
                }
            }
        }
    }
    fn new_text(&mut self, protocol: Protocol, connection: u64) -> TextKey {
        let id = self.id();
        let mut o = Object {
            protocol,
            connection,
            surface: None,
            entered: false,
            ready: false,
            enabled: false,
            pending_enabled: None,
            serial: 0,
            epoch: 0,
            state: TextState::default(),
            pending: TextState::default(),
        };
        if let Protocol::V3(r) = &o.protocol {
            if let Some((id, s)) = self
                .seat
                .focus
                .and_then(|id| self.surfaces.get(&id).map(|s| (id, s)))
            {
                if s.connection == connection {
                    o.surface = Some(id);
                    o.entered = true;
                    self.text.epoch = self.text.epoch.wrapping_add(1);
                    o.epoch = self.text.epoch;
                    r.enter(&s.resource);
                }
            }
        }
        self.text.objects.insert(id, o);
        TextKey(id)
    }
}
fn surrounding(state: &mut TextState, text: String, cursor: i32, anchor: i32) -> bool {
    if text.len() > 4096
        || cursor < 0
        || anchor < 0
        || !text.is_char_boundary(cursor as usize)
        || !text.is_char_boundary(anchor as usize)
    {
        return false;
    }
    state.text = text;
    state.cursor = cursor as u32;
    state.anchor = anchor as u32;
    true
}
impl GlobalDispatch<m1::ZwpTextInputManagerV1, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<m1::ZwpTextInputManagerV1>,
        _: &(),
        i: &mut DataInit<'_, Self>,
    ) {
        i.init(r, ());
    }
}
impl GlobalDispatch<m3::ZwpTextInputManagerV3, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<m3::ZwpTextInputManagerV3>,
        _: &(),
        i: &mut DataInit<'_, Self>,
    ) {
        i.init(r, ());
    }
}
impl Dispatch<m1::ZwpTextInputManagerV1, ()> for State {
    fn request(
        state: &mut Self,
        c: &Client,
        _: &m1::ZwpTextInputManagerV1,
        req: m1::Request,
        _: &(),
        _: &DisplayHandle,
        i: &mut DataInit<'_, Self>,
    ) {
        if let m1::Request::CreateTextInput { id } = req {
            let key = TextKey(state.next);
            let r = i.init(id, key);
            state.new_text(
                Protocol::V1(r),
                c.get_data::<ClientIdentity>().map_or(0, |c| c.connection),
            );
        }
    }
}
impl Dispatch<m3::ZwpTextInputManagerV3, ()> for State {
    fn request(
        state: &mut Self,
        c: &Client,
        _: &m3::ZwpTextInputManagerV3,
        req: m3::Request,
        _: &(),
        _: &DisplayHandle,
        i: &mut DataInit<'_, Self>,
    ) {
        if let m3::Request::GetTextInput { id, .. } = req {
            let key = TextKey(state.next);
            let r = i.init(id, key);
            state.new_text(
                Protocol::V3(r),
                c.get_data::<ClientIdentity>().map_or(0, |c| c.connection),
            );
        }
    }
}
impl Dispatch<t3::ZwpTextInputV3, TextKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &t3::ZwpTextInputV3,
        req: t3::Request,
        key: &TextKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let Some(o) = state.text.objects.get_mut(&key.0) else {
            return;
        };
        match req {
            t3::Request::Enable => {
                o.pending_enabled = Some(true);
                o.pending = TextState::default();
            }
            t3::Request::Disable => o.pending_enabled = Some(false),
            t3::Request::SetSurroundingText {
                text,
                cursor,
                anchor,
            } => {
                if !surrounding(&mut o.pending, text, cursor, anchor) {
                    r.post_error(0u32, "invalid UTF-8 surrounding text offsets");
                    return;
                }
            }
            t3::Request::SetCursorRectangle {
                x,
                y,
                width,
                height,
            } => {
                if width < 0 || height < 0 {
                    r.post_error(0u32, "invalid caret rectangle");
                    return;
                }
                o.pending.caret = [x, y, width, height];
            }
            t3::Request::SetContentType { hint, purpose } => {
                o.pending.hint = hint.into();
                o.pending.purpose = purpose.into();
            }
            t3::Request::Commit => {
                o.serial = o.serial.wrapping_add(1);
                if let Some(enabled) = o.pending_enabled.take() {
                    o.enabled = enabled && o.entered;
                    state.text.epoch = state.text.epoch.wrapping_add(1);
                    o.epoch = state.text.epoch;
                }
                o.state = o.pending.clone();
                o.ready = o.entered && o.enabled;
            }
            t3::Request::Destroy => {
                state.text.objects.remove(&key.0);
            }
            _ => {}
        }
        state.changed();
    }
    fn destroyed(
        state: &mut Self,
        _: wayland_backend::server::ClientId,
        _: &t3::ZwpTextInputV3,
        key: &TextKey,
    ) {
        state.text.objects.remove(&key.0);
        state.changed();
    }
}
impl Dispatch<t1::ZwpTextInputV1, TextKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &t1::ZwpTextInputV1,
        req: t1::Request,
        key: &TextKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let t1::Request::Activate { surface, .. } = &req {
            let Some(connection) = state.text.objects.get(&key.0).map(|o| o.connection) else {
                return;
            };
            if surface.client().is_none_or(|c| {
                c.get_data::<ClientIdentity>()
                    .is_none_or(|i| i.connection != connection)
            }) {
                r.post_error(0u32, "foreign text surface");
                return;
            }
            let id = surface.data::<crate::scene::SurfaceKey>().map(|k| k.0);
            // One seat has one active v1 text input. Clients such as Weston
            // keep a separate object for each widget and rely on leave to
            // deactivate the previous one. Re-activation is idempotent.
            if state
                .text
                .objects
                .get(&key.0)
                .is_some_and(|o| o.enabled && o.surface == id)
            {
                return;
            }
            for o in state.text.objects.values_mut() {
                if let Protocol::V1(old) = &o.protocol {
                    if o.entered && old.is_alive() {
                        old.leave();
                    }
                    o.entered = false;
                }
                o.enabled = false;
                o.ready = false;
                o.pending_enabled = None;
            }
            state.text.epoch = state.text.epoch.wrapping_add(1);
            let o = state.text.objects.get_mut(&key.0).unwrap();
            o.surface = id;
            o.enabled = true;
            o.epoch = state.text.epoch;
            if id == state.seat.focus {
                o.entered = true;
                r.enter(surface);
                r.modifiers_map(b"Shift\0Control\0Mod1\0Mod4\0".to_vec());
            }
            state.changed();
            return;
        }
        let Some(o) = state.text.objects.get_mut(&key.0) else {
            return;
        };
        match req {
            t1::Request::Deactivate { .. } => {
                if o.entered {
                    r.leave();
                }
                o.entered = false;
                o.ready = false;
                o.enabled = false;
            }
            t1::Request::SetSurroundingText {
                text,
                cursor,
                anchor,
            } => {
                if !surrounding(&mut o.pending, text, cursor as i32, anchor as i32) {
                    r.post_error(0u32, "invalid UTF-8 surrounding text offsets");
                    return;
                }
            }
            t1::Request::SetCursorRectangle {
                x,
                y,
                width,
                height,
            } => o.pending.caret = [x, y, width.max(0), height.max(0)],
            t1::Request::SetContentType { hint, purpose } => {
                o.pending.hint = hint.into();
                o.pending.purpose = purpose.into();
            }
            t1::Request::CommitState { serial } => {
                o.serial = serial;
                o.state = o.pending.clone();
                o.ready = o.entered && o.enabled;
            }
            t1::Request::ShowInputPanel => r.input_panel_state(1),
            t1::Request::HideInputPanel => r.input_panel_state(0),
            t1::Request::Reset => {
                state.text.epoch = state.text.epoch.wrapping_add(1);
                o.epoch = state.text.epoch;
            }
            _ => {}
        }
        state.changed();
    }
    fn destroyed(
        state: &mut Self,
        _: wayland_backend::server::ClientId,
        _: &t1::ZwpTextInputV1,
        key: &TextKey,
    ) {
        state.text.objects.remove(&key.0);
        state.changed();
    }
}
