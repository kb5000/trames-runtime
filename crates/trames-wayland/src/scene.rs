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
impl WindowSnapshot {
    /// Logical scene extent, including popups/CSD shadows outside root geometry.
    /// The native UI intersects this with its actual workspace before allocating
    /// a drawable. Wide arithmetic prevents hostile positions wrapping bounds.
    pub fn bounds(&self) -> [i32; 4] {
        let (mut x, mut y, mut r, mut b) =
            (0i64, 0i64, i64::from(self.width), i64::from(self.height));
        for image in &self.scene {
            let (w, h) = image.buffer.dimensions();
            let (w, h) = if image.transform & 1 != 0 {
                (h, w)
            } else {
                (w, h)
            };
            let scale = i64::from(image.scale.max(1));
            let (ix, iy) = (i64::from(image.x), i64::from(image.y));
            x = x.min(ix);
            y = y.min(iy);
            r = r.max(ix + i64::from(w) / scale);
            b = b.max(iy + i64::from(h) / scale);
        }
        let x = x.clamp(-4096, 4096);
        let y = y.clamp(-4096, 4096);
        let r = r.clamp(x + 1, 8192);
        let b = b.clamp(y + 1, 8192);
        [x as i32, y as i32, (r - x) as i32, (b - y) as i32]
    }
}
#[derive(Clone)]
pub struct SurfaceImage {
    pub surface: u64,
    pub x: i32,
    pub y: i32,
    pub scale: i32,
    pub transform: u32,
    pub buffer: ImageBuffer,
}
#[derive(Clone)]
pub enum ImageBuffer {
    Shm(Arc<BufferLease>),
    Gpu(Arc<dyn crate::GpuImage>),
}
impl ImageBuffer {
    pub fn dimensions(&self) -> (u32, u32) {
        match self {
            Self::Shm(b) => (b.pixels.width, b.pixels.height),
            Self::Gpu(g) => g.dimensions(),
        }
    }
    pub fn shm(&self) -> Option<&ShmBuffer> {
        match self {
            Self::Shm(b) => Some(&b.pixels),
            Self::Gpu(_) => None,
        }
    }
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    None,
    Top,
    Popup,
    Subsurface,
    Cursor,
}
pub(crate) struct Surface {
    pub role: Role,
    pub dismissed: bool,
    pub resource: WlSurface,
    pub connection: u64,
    pub xdg: Option<XdgSurface>,
    pub top: Option<XdgToplevel>,
    pub popup: Option<XdgPopup>,
    pub reposition: Option<u32>,
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
    pub current: Option<ImageBuffer>,
    pub gpu_pending: VecDeque<Arc<dyn crate::GpuImage>>,
    pub gpu_presented: bool,
    pub gpu_owner: Arc<std::sync::atomic::AtomicU64>,
    pub gpu_budget: crate::GpuBudget,
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
            role: Role::None,
            dismissed: false,
            xdg: None,
            top: None,
            popup: None,
            reposition: None,
            parent: None,
            children: Vec::new(),
            sub: None,
            cached: None,
            title: String::new(),
            app_id: String::new(),
            size: (640, 480),
            mode: WindowMode::Floating,
            requested_size: (0, 0),
            restore_size: (640, 480),
            pending_buffer: None,
            current: None,
            gpu_pending: VecDeque::new(),
            gpu_presented: true,
            gpu_owner: Arc::default(),
            gpu_budget: Default::default(),
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
        if s.dismissed {
            return;
        }
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
