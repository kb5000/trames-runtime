// SPDX-License-Identifier: GPL-3.0-or-later
//! Synchronized subsurface commits and parent-double-buffered positions/stacking.
use super::*;
use crate::scene::*;
use wayland_server::protocol::{wl_subcompositor as sc, wl_subsurface as ss};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};
pub(crate) fn globals(h: &DisplayHandle) {
    h.create_global::<State, sc::WlSubcompositor, _>(1, ());
}
impl State {
    pub(crate) fn is_descendant(&self, mut id: u64, ancestor: u64) -> bool {
        for _ in 0..256 {
            if id == ancestor {
                return true;
            }
            let Some((parent, ..)) = self.surfaces.get(&id).and_then(|s| s.parent) else {
                return false;
            };
            id = parent;
        }
        true
    }
    pub(crate) fn effectively_synchronized(&self, mut id: u64) -> bool {
        for _ in 0..256 {
            let Some(s) = self.surfaces.get(&id) else {
                return false;
            };
            let Some(sub) = &s.sub else { return false };
            if sub.synchronized {
                return true;
            }
            let Some((parent, ..)) = s.parent else {
                return false;
            };
            id = parent;
        }
        true
    }
    pub(crate) fn apply_children(&mut self, parent: u64) {
        let children = self
            .surfaces
            .get(&parent)
            .map(|s| s.children.clone())
            .unwrap_or_default();
        for id in children {
            let Some(s) = self.surfaces.get_mut(&id) else {
                continue;
            };
            let Some(sub) = &mut s.sub else { continue };
            if let Some((x, y)) = sub.pending_position.take() {
                s.parent = Some((parent, x, y));
                self.revision = self.revision.wrapping_add(1);
                s.revision = self.revision;
            }
            let stack = sub.pending_stack.take();
            let cached = s.cached.take();
            if let Some((sibling, above)) = stack {
                let below = if sibling == parent {
                    !above
                } else {
                    self.surfaces
                        .get(&sibling)
                        .and_then(|s| s.sub.as_ref())
                        .is_some_and(|s| s.below)
                };
                if let Some(p) = self.surfaces.get_mut(&parent) {
                    p.children.retain(|c| *c != id);
                    let index = if sibling == parent {
                        if above {
                            0
                        } else {
                            p.children.len()
                        }
                    } else {
                        p.children
                            .iter()
                            .position(|c| *c == sibling)
                            .map(|i| i + usize::from(above))
                            .unwrap_or(p.children.len())
                    };
                    p.children.insert(index, id);
                }
                if let Some(sub) = self.surfaces.get_mut(&id).and_then(|s| s.sub.as_mut()) {
                    sub.below = below;
                }
                self.changed();
                if let Some(p) = self.surfaces.get_mut(&parent) {
                    p.revision = self.revision;
                }
            }
            if let Some(cached) = cached {
                self.apply_commit(id, cached);
                self.apply_children(id);
            }
        }
    }
}
impl GlobalDispatch<sc::WlSubcompositor, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<sc::WlSubcompositor>,
        _: &(),
        i: &mut DataInit<'_, Self>,
    ) {
        i.init(r, ());
    }
}
impl Dispatch<sc::WlSubcompositor, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &sc::WlSubcompositor,
        req: sc::Request,
        _: &(),
        _: &DisplayHandle,
        i: &mut DataInit<'_, Self>,
    ) {
        match req {
            sc::Request::Destroy => {}
            sc::Request::GetSubsurface {
                id,
                surface,
                parent,
            } => {
                let Some(child) = surface.data::<SurfaceKey>().copied() else {
                    i.post_error(id, 0u32, "foreign child");
                    return;
                };
                let Some(parent) = parent.data::<SurfaceKey>().copied() else {
                    i.post_error(id, 0u32, "foreign parent");
                    return;
                };
                if state.is_descendant(parent.0, child.0) {
                    i.post_error(id, 0u32, "subsurface cycle");
                    return;
                }
                let parent_connection = state.surfaces.get(&parent.0).map(|s| s.connection);
                let Some(s) = state.surfaces.get_mut(&child.0) else {
                    return;
                };
                if parent_connection != Some(s.connection)
                    || s.xdg.is_some()
                    || s.sub.is_some()
                    || s.parent.is_some()
                {
                    i.post_error(id, 0u32, "surface has a role or invalid parent");
                    return;
                }
                i.init(id, child);
                s.parent = Some((parent.0, 0, 0));
                s.sub = Some(Subsurface {
                    synchronized: true,
                    below: false,
                    pending_position: None,
                    pending_stack: None,
                });
                state
                    .surfaces
                    .get_mut(&parent.0)
                    .unwrap()
                    .children
                    .push(child.0);
                state.changed();
            }
            _ => r.post_error(0u32, "unsupported subcompositor request"),
        }
    }
}
impl Dispatch<ss::WlSubsurface, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &ss::WlSubsurface,
        req: ss::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let Some(s) = state.surfaces.get_mut(&key.0) else {
            return;
        };
        let Some(sub) = &mut s.sub else { return };
        match req {
            ss::Request::Destroy => {
                if let Some((parent, ..)) = s.parent.take() {
                    if let Some(p) = state.surfaces.get_mut(&parent) {
                        p.children.retain(|id| *id != key.0);
                    }
                }
                if let Some(s) = state.surfaces.get_mut(&key.0) {
                    s.sub = None;
                    s.cached = None;
                    s.current = None;
                }
                state.changed();
            }
            ss::Request::SetPosition { x, y } => sub.pending_position = Some((x, y)),
            ss::Request::SetSync => sub.synchronized = true,
            ss::Request::SetDesync => {
                sub.synchronized = false;
                if !state.effectively_synchronized(key.0) {
                    if let Some(cached) =
                        state.surfaces.get_mut(&key.0).and_then(|s| s.cached.take())
                    {
                        state.apply_commit(key.0, cached);
                        state.apply_children(key.0);
                    }
                }
            }
            ss::Request::PlaceAbove { ref sibling } | ss::Request::PlaceBelow { ref sibling } => {
                let above = matches!(req, ss::Request::PlaceAbove { .. });
                let sibling = sibling.data::<SurfaceKey>().copied();
                let parent = s.parent.map(|p| p.0);
                let valid = sibling.is_some_and(|id| {
                    id.0 != key.0
                        && (Some(id.0) == parent
                            || state
                                .surfaces
                                .get(&id.0)
                                .and_then(|s| s.parent)
                                .map(|p| p.0)
                                == parent)
                });
                if !valid {
                    r.post_error(0u32, "stacking target is not a parent or sibling");
                    return;
                }
                state
                    .surfaces
                    .get_mut(&key.0)
                    .unwrap()
                    .sub
                    .as_mut()
                    .unwrap()
                    .pending_stack = Some((sibling.unwrap().0, above));
            }
            _ => {}
        }
    }
}
