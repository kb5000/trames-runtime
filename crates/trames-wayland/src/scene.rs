// SPDX-License-Identifier: GPL-3.0-or-later
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, Weak},
};
use trames_shared::{Mapping, SharedFile};
use wayland_protocols::xdg::shell::server::{
    xdg_popup::XdgPopup, xdg_surface::XdgSurface, xdg_toplevel::XdgToplevel,
};
use wayland_server::{
    protocol::{wl_buffer::WlBuffer, wl_callback::WlCallback, wl_surface::WlSurface},
    Resource,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowMode {
    Floating,
    Minimized,
    Maximized,
}
#[derive(Clone)]
pub struct WindowSnapshot {
    pub id: u64,
    pub connection: u64,
    pub title: String,
    pub app_id: String,
    pub width: u32,
    pub height: u32,
    pub mode: WindowMode,
    pub scene: Vec<SurfaceImage>,
    pub revision: u64,
}
#[derive(Clone)]
pub struct SurfaceImage {
    pub surface: u64,
    pub x: i32,
    pub y: i32,
    pub scale: i32,
    pub transform: u32,
    pub buffer: Arc<BufferLease>,
}
/// Host buffer capability. It contains no guest pointer, FD number or VM borrow.
pub struct ShmBuffer {
    pub id: u64,
    pub file: SharedFile,
    pub mapping: Mapping,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub alpha: bool,
}
/// A scene/GPU completion retains this lease. Release only follows its final use.
pub(crate) struct BufferData {
    pub pixels: Arc<ShmBuffer>,
    pub lease: Mutex<Weak<BufferLease>>,
}
impl BufferLease {
    pub(crate) fn acquire(resource: WlBuffer) -> Option<Arc<Self>> {
        let data = resource.data::<BufferData>()?;
        let mut weak = data.lease.lock().ok()?;
        if let Some(lease) = weak.upgrade() {
            return Some(lease);
        }
        let lease = Arc::new(Self {
            pixels: data.pixels.clone(),
            resource: resource.clone(),
        });
        *weak = Arc::downgrade(&lease);
        Some(lease)
    }
}
pub struct BufferLease {
    pub pixels: Arc<ShmBuffer>,
    pub(crate) resource: WlBuffer,
}
impl Drop for BufferLease {
    fn drop(&mut self) {
        if self.resource.is_alive() {
            self.resource.release();
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct SurfaceKey(pub u64);
pub(crate) struct Subsurface {
    pub synchronized: bool,
    pub below: bool,
    pub pending_position: Option<(i32, i32)>,
    pub pending_stack: Option<(u64, bool)>,
}
pub(crate) struct CachedCommit {
    pub buffer: Option<Option<Arc<BufferLease>>>,
    pub callbacks: Vec<WlCallback>,
    pub scale: i32,
    pub geometry: Option<(i32, i32, u32, u32)>,
    pub offset: Option<(i32, i32)>,
    pub transform: u32,
    pub input: Option<Option<Region>>,
}
impl CachedCommit {
    pub fn merge(&mut self, mut next: Self) {
        if next.buffer.is_some() {
            self.buffer = next.buffer;
        }
        self.callbacks.append(&mut next.callbacks);
        self.scale = next.scale;
        self.transform = next.transform;
        if let Some((x, y)) = next.offset {
            let (a, b) = self.offset.unwrap_or_default();
            self.offset = Some((a.saturating_add(x), b.saturating_add(y)));
        }
        if next.input.is_some() {
            self.input = next.input;
        }
        if next.geometry.is_some() {
            self.geometry = next.geometry;
        }
    }
}
#[derive(Clone, Default)]
pub(crate) struct Region(pub Vec<(i32, i32, i32, i32, bool)>);
impl Region {
    pub fn contains(&self, x: f64, y: f64) -> bool {
        self.0
            .iter()
            .rev()
            .find(|&&(rx, ry, w, h, _)| {
                x >= f64::from(rx)
                    && y >= f64::from(ry)
                    && x < f64::from(rx) + f64::from(w)
                    && y < f64::from(ry) + f64::from(h)
            })
            .is_some_and(|r| r.4)
    }
}
pub(crate) struct Surface {
    pub resource: WlSurface,
    pub connection: u64,
    pub xdg: Option<XdgSurface>,
    pub top: Option<XdgToplevel>,
    pub popup: Option<XdgPopup>,
    pub parent: Option<(u64, i32, i32)>,
    pub children: Vec<u64>,
    pub sub: Option<Subsurface>,
    pub cached: Option<CachedCommit>,
    pub title: String,
    pub app_id: String,
    pub size: (u32, u32),
    pub mode: WindowMode,
    pub requested_size: (u32, u32),
    pub restore_size: (u32, u32),
    pub pending_buffer: Option<Option<WlBuffer>>,
    pub current: Option<Arc<BufferLease>>,
    pub pending_callbacks: Vec<WlCallback>,
    pub callbacks: VecDeque<(u64, Vec<WlCallback>)>,
    pub configured: bool,
    pub acknowledged: bool,
    pub outstanding: VecDeque<u32>,
    pub scale: i32,
    pub pending_scale: i32,
    pub geometry: Option<(i32, i32, u32, u32)>,
    pub pending_geometry: Option<(i32, i32, u32, u32)>,
    pub revision: u64,
    pub offset: (i32, i32),
    pub pending_offset: Option<(i32, i32)>,
    pub transform: u32,
    pub pending_transform: u32,
    pub input: Option<Region>,
    pub pending_input: Option<Option<Region>>,
}
impl Surface {
    pub fn take_pending(&mut self) -> CachedCommit {
        CachedCommit {
            buffer: self
                .pending_buffer
                .take()
                .map(|b| b.and_then(BufferLease::acquire)),
            callbacks: std::mem::take(&mut self.pending_callbacks),
            scale: self.pending_scale,
            geometry: self.pending_geometry.take(),
            offset: self.pending_offset.take(),
            transform: self.pending_transform,
            input: self.pending_input.take(),
        }
    }
    pub fn new(resource: WlSurface, connection: u64) -> Self {
        Self {
            resource,
            connection,
            xdg: None,
            top: None,
            popup: None,
            parent: None,
            children: Vec::new(),
            sub: None,
            cached: None,
            title: String::new(),
            app_id: String::new(),
            size: (640, 480),
            mode: WindowMode::Floating,
            requested_size: (640, 480),
            restore_size: (640, 480),
            pending_buffer: None,
            current: None,
            pending_callbacks: Vec::new(),
            callbacks: VecDeque::new(),
            configured: false,
            acknowledged: false,
            outstanding: VecDeque::new(),
            scale: 1,
            pending_scale: 1,
            geometry: None,
            pending_geometry: None,
            revision: 0,
            offset: (0, 0),
            pending_offset: None,
            transform: 0,
            pending_transform: 0,
            input: None,
            pending_input: None,
        }
    }
}
pub(crate) fn snapshot(surfaces: &BTreeMap<u64, Surface>) -> Vec<WindowSnapshot> {
    fn images(
        surfaces: &BTreeMap<u64, Surface>,
        id: u64,
        x: i32,
        y: i32,
        out: &mut Vec<SurfaceImage>,
    ) {
        let Some(s) = surfaces.get(&id) else { return };
        // Subsurface stacking is relative to the parent and its siblings.
        for below in [true, false] {
            if !below {
                if let Some(buffer) = &s.current {
                    out.push(SurfaceImage {
                        surface: id,
                        x,
                        y,
                        scale: s.scale,
                        transform: s.transform,
                        buffer: buffer.clone(),
                    });
                }
            }
            for &child in &s.children {
                if let Some(c) = surfaces.get(&child) {
                    if c.sub.as_ref().is_some_and(|s| s.below) != below {
                        continue;
                    }
                    if let Some((_, mut cx, mut cy)) = c.parent {
                        if c.popup.is_some() {
                            let (px, py, ..) = s.geometry.unwrap_or((0, 0, 0, 0));
                            let (gx, gy, ..) = c.geometry.unwrap_or((0, 0, 0, 0));
                            cx = cx.saturating_add(px).saturating_sub(gx);
                            cy = cy.saturating_add(py).saturating_sub(gy);
                        }
                        images(
                            surfaces,
                            child,
                            x.saturating_add(cx),
                            y.saturating_add(cy),
                            out,
                        );
                    }
                }
            }
        }
    }
    surfaces
        .iter()
        .filter(|(_, s)| s.top.is_some() && s.current.is_some())
        .map(|(&id, s)| {
            let mut scene = Vec::new();
            let (gx, gy, ..) = s.geometry.unwrap_or((0, 0, 0, 0));
            images(
                surfaces,
                id,
                gx.saturating_neg(),
                gy.saturating_neg(),
                &mut scene,
            );
            WindowSnapshot {
                id,
                connection: s.connection,
                title: s.title.clone(),
                app_id: s.app_id.clone(),
                width: s.size.0,
                height: s.size.1,
                mode: s.mode,
                revision: scene
                    .iter()
                    .filter_map(|image| surfaces.get(&image.surface))
                    .map(|s| s.revision)
                    .max()
                    .unwrap_or(s.revision)
                    .max(s.revision),
                scene,
            }
        })
        .collect()
}
