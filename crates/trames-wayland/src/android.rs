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
    alpha: bool,
    lease: Mutex<Weak<Lease>>,
}
struct Lease {
    image: Arc<dyn trames_graphics::Image>,
    texture: Arc<trames_graphics::Texture>,
    alpha: bool,
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
    fn native_handle(&self) -> trames_graphics::NativeHandle {
        self.texture.native_handle()
    }
    fn ready(&self) -> io::Result<bool> {
        Ok(true)
    }
    fn has_alpha(&self) -> bool {
        self.alpha
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
            alpha: data.alpha,
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
                if width <= 0 || height <= 0 || info.format != native_format || stride <= 0 {
                    resource.post_error(1u32, format!(
                        "native image geometry mismatch: requested {width}x{height} stride={stride} format={format}, image {}x{} pitch={} format={:?}",
                        info.width, info.height, info.pitch, info.format));
                    return;
                }
                // The retained native plane owns its geometry and row layout.
                // Waydroid's separate HIDL size/stride metadata can describe the
                // next display configuration while its attached target is still
                // the old image. Those duplicate hints must not disconnect the
                // compositor. Texture and viewport bounds use actual ImageInfo;
                // no guest-provided dimensions address or resize this storage.
                let Ok(texture) = trames_graphics::Context::display_texture(image.as_ref()) else {
                    resource.post_error(0u32, "native texture unavailable");
                    return;
                };
                init.init(
                    id,
                    Buffer {
                        image,
                        texture,
                        alpha: matches!(format, 1 | 5),
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

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use trames_shared::{NativeSocket, SharedFile};

    fn message(id: u32, opcode: u32, words: &[u32]) -> Vec<u8> {
        [id, (((words.len() + 2) * 4) as u32) << 16 | opcode]
            .into_iter()
            .chain(words.iter().copied())
            .flat_map(u32::to_ne_bytes)
            .collect()
    }

    #[test]
    fn native_plane_bounds_survive_stale_waydroid_resize_metadata() {
        for format in [1, 5] {
            let mut compositor = Compositor::new().unwrap();
            let (client, server) = UnixStream::pair().unwrap();
            client.set_nonblocking(true).unwrap();
            compositor
                .connect(
                    server,
                    ClientIdentity {
                        connection: 1,
                        pid: 7,
                        uid: 0,
                        gid: 0,
                    },
                )
                .unwrap();
            let socket = NativeSocket::from(client);
            socket.send_msg(&message(1, 1, &[2]), &[]).unwrap();
            compositor.dispatch().unwrap();
            let mut globals = vec![0; 65536];
            let count = socket
                .rcv_msg(&mut globals, &mut Default::default())
                .unwrap();
            let mut name = None;
            let mut at = 0;
            while at < count {
                let size = (u32::from_ne_bytes(globals[at + 4..at + 8].try_into().unwrap()) >> 16)
                    as usize;
                if globals[at..at + size]
                    .windows(14)
                    .any(|s| s == b"android_wlegl\0")
                {
                    name = Some(u32::from_ne_bytes(
                        globals[at + 8..at + 12].try_into().unwrap(),
                    ));
                }
                at += size;
            }
            let mut bind = vec![name.unwrap(), 14];
            let mut interface = b"android_wlegl\0".to_vec();
            interface.resize(16, 0);
            bind.extend(
                interface
                    .chunks_exact(4)
                    .map(|s| u32::from_ne_bytes(s.try_into().unwrap())),
            );
            bind.extend([1, 3]);
            socket.send_msg(&message(2, 0, &bind), &[]).unwrap();
            compositor.dispatch().unwrap();
            let image = trames_graphics::Context::default()
                .allocate(trames_graphics::Format::Rgba8, 65, 37)
                .unwrap();
            let file = SharedFile::anonymous().unwrap();
            file.attach(trames_graphics::ImageAttachment(image.clone()))
                .unwrap();
            let (fd, transfer) = file.export().unwrap();
            socket
                .send_msg(
                    &message(3, 0, &[4, 1, 40, 0x54524742, 65, 37, 1, 80, 0, 0, 0, 0, 0]),
                    &[],
                )
                .unwrap();
            socket.send_msg(&message(4, 0, &[]), &[fd]).unwrap();
            // The old target FD accompanies dimensions/stride from the next mode.
            socket
                .send_msg(&message(3, 1, &[5, 1088, 780, 1088, format, 0, 4]), &[])
                .unwrap();
            compositor.dispatch().unwrap();
            assert!(transfer.claimed());
            let resource = compositor.clients.get(&1).and_then(|client| {
                client
                    .object_from_protocol_id::<WlBuffer>(&compositor.display.handle(), 5)
                    .ok()
            });
            if format == 1 {
                let resource =
                    resource.expect("resize metadata must not disconnect the image owner");
                drop(file);
                drop(image);
                let lease = acquire(&resource).unwrap();
                assert_eq!(lease.dimensions(), (65, 37));
                assert!(lease.has_alpha());
            } else {
                assert!(
                    resource.is_none(),
                    "incompatible pixel interpretation must still fail"
                );
            }
        }
    }
}
