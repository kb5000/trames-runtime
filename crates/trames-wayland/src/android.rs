// SPDX-License-Identifier: GPL-3.0-or-later
//! Waydroid's original android_wlegl v1 protocol, over retained native planes.
//! No guest pointer, raw host FD import, DRM driver or readback presentation.
use super::*;
use std::sync::{Mutex, Weak};
use wayland_server::protocol::wl_buffer::WlBuffer;
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New};
#[allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
#[allow(unused_imports, unused_unsafe, unused_variables, clippy::all)]
mod wire {
    use wayland_server;
    use wayland_server::protocol::wl_buffer;
    pub mod __interfaces {
        use wayland_server::protocol::__interfaces::*;
        wayland_scanner::generate_interfaces!("wayland-android.xml");
    }
    use self::__interfaces::*;
    wayland_scanner::generate_server_code!("wayland-android.xml");
}
use wire::{
    android_wlegl::{AndroidWlegl, Request},
    android_wlegl_handle::{AndroidWleglHandle, Request as HandleRequest},
};
#[derive(Default)]
struct Handle {
    plane: Mutex<Option<Arc<dyn trames_graphics::Image>>>,
}
pub(crate) struct Buffer {
    image: Arc<dyn trames_graphics::Image>,
    texture: Arc<trames_graphics::Texture>,
    lease: Mutex<Weak<Lease>>,
}
struct Lease {
    image: Arc<dyn trames_graphics::Image>,
    texture: Arc<trames_graphics::Texture>,
    resource: WlBuffer,
}
// SAFETY: the buffer owns original native storage and texture. Waydroid HWC
// waits its producer acquire fence before attaching this buffer. wl_buffer.release
// follows the last scene/UI GPU lease, so producer reuse cannot precede reads.
unsafe impl GpuImage for Lease {
    fn dimensions(&self) -> (u32, u32) {
        let info = self.image.info();
        (info.width, info.height)
    }
    fn metal_texture(&self) -> usize {
        self.texture.handle()
    }
    fn ready(&self) -> io::Result<bool> {
        Ok(true)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.resource.is_alive() {
            self.resource.release();
        }
    }
}
pub(crate) fn acquire(resource: &WlBuffer) -> Option<ImageBuffer> {
    let data = resource.data::<Buffer>()?;
    let mut current = data.lease.lock().ok()?;
    let lease = current.upgrade().unwrap_or_else(|| {
        let lease = Arc::new(Lease {
            image: data.image.clone(),
            texture: data.texture.clone(),
            resource: resource.clone(),
        });
        *current = Arc::downgrade(&lease);
        lease
    });
    Some(ImageBuffer::Gpu(lease))
}
pub(crate) fn globals(display: &DisplayHandle) {
    display.create_global::<State, AndroidWlegl, _>(1, ());
}
impl GlobalDispatch<AndroidWlegl, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        new: New<AndroidWlegl>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(new, ());
    }
}
impl Dispatch<AndroidWlegl, ()> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        resource: &AndroidWlegl,
        request: Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            Request::CreateHandle { id, num_fds, ints } => {
                if num_fds != 1
                    || ints.len() != 40
                    || u32::from_ne_bytes(ints[..4].try_into().unwrap()) != 0x54524742
                {
                    resource.post_error(0u32, "unsupported native image handle");
                    return;
                }
                init.init(id, Handle::default());
            }
            Request::CreateBuffer {
                id,
                width,
                height,
                stride,
                format,
                native_handle,
                ..
            } => {
                let image = native_handle
                    .data::<Handle>()
                    .and_then(|h| h.plane.lock().ok()?.clone());
                let Some(image) = image else {
                    resource.post_error(0u32, "native image FD missing");
                    return;
                };
                let info = image.info();
                let native_format = match format {
                    1 | 2 => trames_graphics::Format::Rgba8,
                    5 => trames_graphics::Format::Bgra8,
                    _ => {
                        resource.post_error(1u32, "unsupported pixel format");
                        return;
                    }
                };
                if width <= 0
                    || height <= 0
                    || info.width != width as u32
                    || info.height != height as u32
                    || info.format != native_format
                    || stride <= 0
                    || stride as u64 * 4 != info.pitch
                {
                    resource.post_error(1u32, "native image geometry mismatch");
                    return;
                }
                let Ok(texture) = trames_graphics::Context::display_texture(image.as_ref()) else {
                    resource.post_error(0u32, "native texture unavailable");
                    return;
                };
                init.init(
                    id,
                    Buffer {
                        image,
                        texture,
                        lease: Mutex::default(),
                    },
                );
            }
            _ => resource.post_error(1u32, "unsupported android_wlegl request"),
        }
    }
}
impl Dispatch<AndroidWleglHandle, Handle> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        resource: &AndroidWleglHandle,
        request: HandleRequest,
        data: &Handle,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let HandleRequest::AddFd { fd } = request {
            let mut image = data.plane.lock().unwrap();
            if image.is_some() {
                resource.post_error(0u32, "too many native image FDs");
                return;
            }
            let imported = trames_shared::SharedFile::import(fd).ok().and_then(|file| {
                file.attachment::<trames_graphics::ImageAttachment>()
                    .map(|a| a.0.clone())
            });
            if imported.is_none() {
                resource.post_error(0u32, "FD is not an original native image");
                return;
            }
            *image = imported;
        }
    }
}
impl Dispatch<WlBuffer, Buffer> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &WlBuffer,
        _: wayland_server::protocol::wl_buffer::Request,
        _: &Buffer,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}
