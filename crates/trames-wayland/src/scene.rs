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
pub(crate) struct Surface {
    pub resource: WlSurface,
    pub connection: u64,
    pub xdg: Option<XdgSurface>,
    pub top: Option<XdgToplevel>,
    pub popup: Option<XdgPopup>,
    pub parent: Option<(u64, i32, i32)>,
    pub children: Vec<u64>,
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
}
impl Surface {
    pub fn new(resource: WlSurface, connection: u64) -> Self {
        Self {
            resource,
            connection,
            xdg: None,
            top: None,
            popup: None,
            parent: None,
            children: Vec::new(),
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
        if let Some(buffer) = &s.current {
            out.push(SurfaceImage {
                surface: id,
                x,
                y,
                scale: s.scale,
                buffer: buffer.clone(),
            });
        }
        for &child in &s.children {
            if let Some((_, cx, cy)) = surfaces.get(&child).and_then(|s| s.parent) {
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
    surfaces
        .iter()
        .filter(|(_, s)| s.top.is_some() && s.current.is_some())
        .map(|(&id, s)| {
            let mut scene = Vec::new();
            images(surfaces, id, 0, 0, &mut scene);
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
