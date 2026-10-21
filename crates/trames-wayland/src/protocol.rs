// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::scene::*;
use std::sync::Mutex;
use wayland_server::protocol::{
    wl_buffer, wl_callback, wl_compositor, wl_output, wl_region, wl_shm, wl_shm_pool, wl_surface,
};
use wayland_server::{
    Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource, WEnum,
};

pub(crate) struct Pool {
    file: trames_shared::SharedFile,
    size: usize,
}
impl State {
    pub fn globals(
        handle: &DisplayHandle,
        xwayland: Arc<std::sync::Mutex<std::collections::BTreeSet<crate::xwm::Identity>>>,
    ) {
        handle.create_global::<Self, wl_compositor::WlCompositor, _>(4, ());
        handle.create_global::<Self, wl_shm::WlShm, _>(1, ());
        handle.create_global::<Self, wl_output::WlOutput, _>(3, ());
        crate::shell::globals(handle);
        crate::input::globals(handle);
        crate::selection::globals(handle);
        crate::text::globals(handle);
        crate::subsurface::globals(handle);
        crate::xwayland::globals(handle, xwayland);
        crate::wsi::globals(handle);
    }
    pub fn id(&mut self) -> u64 {
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .expect("native surface ID exhausted");
        id
    }
    pub fn changed(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }
    pub fn commit(&mut self, id: u64) {
        self.xcommit(id);
        let synchronized = self.effectively_synchronized(id);
        let Some(s) = self.surfaces.get_mut(&id) else {
            return;
        };
        let pending = s.take_pending();
        if synchronized {
            if let Some(cached) = &mut s.cached {
                cached.merge(pending);
            } else {
                s.cached = Some(pending);
            }
            return;
        }
        self.apply_commit(id, pending);
        self.apply_children(id);
    }
    pub(crate) fn apply_commit(&mut self, id: u64, pending: CachedCommit) {
        if matches!(pending.buffer, Some(None)) {
            self.surface_unmapped(id);
        }
        let needs_configure = self
            .surfaces
            .get(&id)
            .is_some_and(|s| s.xdg.is_some() && !s.configured);
        if needs_configure {
            self.configure(id);
        }
        let Some(s) = self.surfaces.get_mut(&id) else {
            return;
        };
        let changed = pending.buffer.is_some()
            || pending.damaged
            || pending.scale != s.scale
            || pending.transform != s.transform
            || pending.input.is_some()
            || pending.offset.is_some()
            || pending.geometry.is_some();
        if let Some(attachment) = pending.buffer {
            if attachment.is_some() && s.xdg.is_some() && !s.acknowledged {
                if let Some(xdg) = &s.xdg {
                    xdg.post_error(3u32, "buffer committed before configure acknowledgement");
                }
                return;
            }
            s.current = attachment.map(ImageBuffer::Shm);
            s.gpu_pending.clear();
        }
        s.scale = pending.scale;
        s.transform = pending.transform;
        if let Some(input) = pending.input {
            s.input = input;
        }
        if let Some((x, y)) = pending.offset {
            s.offset = (s.offset.0.saturating_add(x), s.offset.1.saturating_add(y));
        }
        if let Some(geometry) = pending.geometry {
            s.geometry = Some(geometry);
        }
        if let Some(buffer) = &s.current {
            let (bw, bh) = buffer.dimensions();
            let (w, h) = if s.transform & 1 != 0 {
                (bh, bw)
            } else {
                (bw, bh)
            };
            if !w.is_multiple_of(s.scale as u32) || !h.is_multiple_of(s.scale as u32) {
                s.resource
                    .post_error(2u32, "buffer dimensions must be a multiple of scale");
                return;
            }
            s.size = s
                .geometry
                .map(|(_, _, w, h)| (w, h))
                .unwrap_or((w / s.scale as u32, h / s.scale as u32));
        }
        // A frame callback requests scheduling, not new image content. Reuse
        // the displayed content revision so the existing pacer can deliver it
        // on its timer without republishing/repainting an unchanged scene.
        if changed {
            self.revision = self.revision.wrapping_add(1);
            s.revision = self.revision;
        }
        if !pending.callbacks.is_empty() {
            s.callbacks.push_back((s.revision, pending.callbacks));
        }
        if self.seat.popups.last() == Some(&id)
            && self.surfaces.get(&id).is_some_and(|s| s.current.is_some())
        {
            self.focus_surface(Some(id));
        }
    }
}
impl GlobalDispatch<wl_compositor::WlCompositor, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<wl_compositor::WlCompositor>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(r, ());
    }
}
impl Dispatch<wl_compositor::WlCompositor, ()> for State {
    fn request(
        state: &mut Self,
        client: &Client,
        r: &wl_compositor::WlCompositor,
        request: wl_compositor::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_compositor::Request::CreateSurface { id } => {
                if state.surfaces.len() >= 256 {
                    init.post_error(id, 0u32, "surface limit reached");
                    return;
                }
                let key = SurfaceKey(state.id());
                let surface = init.init(id, key);
                let connection = client
                    .get_data::<ClientIdentity>()
                    .map_or(0, |c| c.connection);
                state
                    .surfaces
                    .insert(key.0, Surface::new(surface, connection));
                state.changed();
            }
            wl_compositor::Request::CreateRegion { id } => {
                init.init(id, Mutex::new(Region::default()));
            }
            _ => r.post_error(0u32, "unsupported compositor request"),
        }
    }
}
impl Dispatch<wl_region::WlRegion, Mutex<Region>> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        r: &wl_region::WlRegion,
        request: wl_region::Request,
        data: &Mutex<Region>,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let (x, y, width, height, add) = match request {
            wl_region::Request::Destroy => return,
            wl_region::Request::Add {
                x,
                y,
                width,
                height,
            } => (x, y, width, height, true),
            wl_region::Request::Subtract {
                x,
                y,
                width,
                height,
            } => (x, y, width, height, false),
            _ => return,
        };
        if width < 0 || height < 0 {
            r.post_error(0u32, "negative region extent");
            return;
        }
        if let Ok(mut region) = data.lock() {
            if region.0.len() >= 1024 {
                r.post_error(0u32, "region operation limit reached");
                return;
            }
            region.0.push((x, y, width, height, add));
        }
    }
}
impl Dispatch<wl_surface::WlSurface, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &wl_surface::WlSurface,
        request: wl_surface::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        let Some(s) = state.surfaces.get_mut(&key.0) else {
            return;
        };
        match request {
            wl_surface::Request::Destroy => {}
            wl_surface::Request::Attach { buffer, x, y } => {
                s.pending_offset = Some((x, y));
                s.pending_buffer = Some(buffer);
            }
            wl_surface::Request::Damage { width, height, .. }
            | wl_surface::Request::DamageBuffer { width, height, .. } => {
                if width < 0 || height < 0 {
                    r.post_error(2u32, "negative damage extent");
                } else if width != 0 && height != 0 {
                    s.pending_damage = true;
                }
            }
            wl_surface::Request::Frame { callback } => {
                if s.pending_callbacks.len()
                    + s.callbacks.iter().map(|(_, c)| c.len()).sum::<usize>()
                    + s.cached.as_ref().map_or(0, |c| c.callbacks.len())
                    >= 256
                {
                    init.post_error(callback, 0u32, "frame callback limit reached");
                    return;
                }
                s.pending_callbacks.push(init.init(callback, ()));
            }
            wl_surface::Request::Commit => state.commit(key.0),
            wl_surface::Request::SetBufferScale { scale } => {
                if !(1..=8).contains(&scale) {
                    r.post_error(0u32, "invalid buffer scale");
                } else {
                    s.pending_scale = scale;
                }
            }
            wl_surface::Request::SetBufferTransform { transform } => {
                let raw: u32 = transform.into();
                if raw > 7 {
                    r.post_error(1u32, "invalid buffer transform");
                } else {
                    s.pending_transform = raw;
                }
            }
            wl_surface::Request::SetInputRegion { region } => {
                s.pending_input = Some(region.and_then(|r| {
                    r.data::<Mutex<Region>>()
                        .and_then(|v| v.lock().ok().map(|v| v.clone()))
                }));
            }
            wl_surface::Request::SetOpaqueRegion { .. } => {}
            _ => r.post_error(0u32, "unsupported surface request"),
        }
    }
    fn destroyed(
        state: &mut Self,
        _: wayland_backend::server::ClientId,
        _: &wl_surface::WlSurface,
        key: &SurfaceKey,
    ) {
        state.surface_unmapped(key.0);
        if let Some(s) = state.surfaces.remove(&key.0) {
            if let Some((parent, ..)) = s.parent {
                if let Some(p) = state.surfaces.get_mut(&parent) {
                    p.children.retain(|id| *id != key.0);
                }
            }
            for child in s.children {
                if let Some(c) = state.surfaces.get_mut(&child) {
                    c.parent = None;
                    if let Some(p) = &c.popup {
                        p.popup_done();
                    }
                }
            }
            state.seat.popups.retain(|id| *id != key.0);
            state.changed();
        }
    }
}
impl Dispatch<wl_callback::WlCallback, ()> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &wl_callback::WlCallback,
        _: wl_callback::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}
impl GlobalDispatch<wl_shm::WlShm, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<wl_shm::WlShm>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        let r = init.init(r, ());
        r.format(wl_shm::Format::Argb8888);
        r.format(wl_shm::Format::Xrgb8888);
    }
}
impl Dispatch<wl_shm::WlShm, ()> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        r: &wl_shm::WlShm,
        request: wl_shm::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_shm::Request::CreatePool { id, fd, size } => {
                let file = trames_shared::SharedFile::import(fd);
                match file {
                    Ok(file) if size > 0 && (size as usize) <= file.len() => {
                        init.init(
                            id,
                            Mutex::new(Pool {
                                file,
                                size: size as usize,
                            }),
                        );
                    }
                    _ => init.post_error(id, 1u32, "invalid shared memory pool"),
                }
            }
            _ => r.post_error(1u32, "unsupported shared memory request"),
        }
    }
}
impl Dispatch<wl_shm_pool::WlShmPool, Mutex<Pool>> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &wl_shm_pool::WlShmPool,
        request: wl_shm_pool::Request,
        data: &Mutex<Pool>,
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        let Ok(mut pool) = data.lock() else { return };
        match request {
            wl_shm_pool::Request::Destroy => {}
            wl_shm_pool::Request::Resize { size } => {
                if size < 0 || (size as usize) < pool.size || (size as usize) > pool.file.len() {
                    r.post_error(1u32, "invalid pool resize");
                } else {
                    pool.size = size as usize;
                }
            }
            wl_shm_pool::Request::CreateBuffer {
                id,
                offset,
                width,
                height,
                stride,
                format,
            } => {
                let alpha = match format {
                    WEnum::Value(wl_shm::Format::Argb8888) => true,
                    WEnum::Value(wl_shm::Format::Xrgb8888) => false,
                    _ => {
                        init.post_error(id, 0u32, "unsupported shared memory format");
                        return;
                    }
                };
                let valid = offset >= 0
                    && width > 0
                    && height > 0
                    && width <= 4096
                    && height <= 4096
                    && stride >= width * 4;
                if !valid {
                    init.post_error(id, 1u32, "invalid shared memory buffer extent");
                    return;
                }
                let bytes = (height as usize)
                    .checked_sub(1)
                    .and_then(|rows| rows.checked_mul(stride as usize))
                    .and_then(|n| n.checked_add(width as usize * 4));
                let end = bytes.and_then(|n| (offset as usize).checked_add(n));
                if !valid || end.is_none_or(|end| end > pool.size || end > pool.file.len()) {
                    init.post_error(id, 1u32, "shared memory buffer exceeds pool");
                    return;
                }
                let map = pool.file.map(offset as usize, bytes.unwrap());
                match map {
                    Ok(mapping) => {
                        let pixels = Arc::new(ShmBuffer {
                            id: state.id(),
                            file: pool.file.clone(),
                            mapping,
                            width: width as u32,
                            height: height as u32,
                            stride: stride as u32,
                            alpha,
                        });
                        init.init(
                            id,
                            BufferData {
                                pixels,
                                lease: Mutex::default(),
                            },
                        );
                    }
                    Err(_) => init.post_error(id, 1u32, "shared memory mapping failed"),
                }
            }
            _ => r.post_error(1u32, "unsupported pool request"),
        }
    }
}
impl Dispatch<wl_buffer::WlBuffer, BufferData> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &wl_buffer::WlBuffer,
        _: wl_buffer::Request,
        _: &BufferData,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}
impl GlobalDispatch<wl_output::WlOutput, ()> for State {
    fn bind(
        state: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<wl_output::WlOutput>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        let r = init.init(r, ());
        r.geometry(
            0,
            0,
            260,
            195,
            wl_output::Subpixel::Unknown,
            "Trames".into(),
            "Wayland output".into(),
            wl_output::Transform::Normal,
        );
        r.mode(
            wl_output::Mode::Current | wl_output::Mode::Preferred,
            state.viewport.0 as i32,
            state.viewport.1 as i32,
            crate::frame::REFRESH_MILLIHERTZ,
        );
        if r.version() >= 2 {
            r.scale(1);
            r.done();
        }
    }
}
impl Dispatch<wl_output::WlOutput, ()> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &wl_output::WlOutput,
        _: wl_output::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}
