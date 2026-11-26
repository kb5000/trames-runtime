// SPDX-License-Identifier: GPL-3.0-or-later
//! Native capabilities retain platform resources, layout and completion authority.
use std::{io, sync::Arc};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDevice {
    Metal(usize),
    Vulkan {
        instance: u64,
        physical: u64,
        device: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VulkanImage {
    pub instance: u64,
    pub physical: u64,
    pub device: u64,
    pub image: u64,
    pub format: u32,
    pub layout: u32,
}
/// A retained native Vulkan queue, shared only by actual producer/presenter
/// submissions. Its object-level lock satisfies Vulkan external synchronization;
/// ordinary CPU execution and unrelated queues never acquire it.
#[derive(Clone)]
pub struct VulkanQueue {
    device: NativeDevice,
    family: u32,
    queue: u64,
    surfaces: u32,
    synchronization: Arc<std::sync::Mutex<()>>,
    _owner: Arc<dyn Send + Sync>,
}
impl VulkanQueue {
    /// # Safety
    /// The owner retains this exact device/instance/queue. Every native access
    /// to this queue uses the same synchronization object through final use.
    pub unsafe fn retained(
        device: NativeDevice,
        family: u32,
        queue: u64,
        surfaces: u32,
        synchronization: Arc<std::sync::Mutex<()>>,
        owner: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            device,
            family,
            queue,
            surfaces,
            synchronization,
            _owner: owner,
        }
    }
    pub fn device(&self) -> NativeDevice {
        self.device
    }
    pub fn family(&self) -> u32 {
        self.family
    }
    pub fn raw(&self) -> u64 {
        self.queue
    }
    pub fn supports_xcb(&self) -> bool {
        self.surfaces & 1 != 0
    }
    pub fn supports_wayland(&self) -> bool {
        self.surfaces & 2 != 0
    }
    pub fn synchronized<T>(&self, body: impl FnOnce() -> T) -> T {
        let _guard = self.synchronization.lock().unwrap();
        body()
    }
}
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NativeHandle {
    /// Protocol-only resources cannot be submitted to a physical presenter.
    Empty,
    MetalTexture(usize),
    VulkanImage(VulkanImage),
    #[cfg(unix)]
    DmaBuf(Arc<DmaBuf>),
}
impl NativeHandle {
    pub fn metal_texture(&self) -> io::Result<usize> {
        match self {
            Self::MetalTexture(value) if *value != 0 => Ok(*value),
            _ => Err(io::Error::from_raw_os_error(95)),
        }
    }
}
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceKind {
    SyncFile,
    Notification,
}
#[cfg(unix)]
#[derive(Debug)]
pub struct FenceFd {
    fd: std::os::fd::OwnedFd,
    kind: FenceKind,
}
#[cfg(unix)]
impl FenceFd {
    /// # Safety
    /// The owned descriptor is an exported sync_file from the producing API.
    pub unsafe fn sync_file(fd: std::os::fd::OwnedFd) -> Self {
        Self {
            fd,
            kind: FenceKind::SyncFile,
        }
    }
    pub fn notification(fd: std::os::fd::OwnedFd) -> Self {
        Self {
            fd,
            kind: FenceKind::Notification,
        }
    }
    pub fn kind(&self) -> FenceKind {
        self.kind
    }
    pub fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.fd.as_fd()
    }
    pub fn ready(&self) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut fd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut fd, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if fd.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if fd.revents & libc::POLLERR != 0 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(fd.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }
    pub fn interest(&self, wait: &mut trames_shared::HostWait) -> io::Result<()> {
        wait.watch(self.descriptor(), false)
    }
}
#[cfg(unix)]
#[derive(Debug)]
pub struct DmaObject {
    pub fd: std::os::fd::OwnedFd,
    pub size: u64,
    pub modifier: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaneLayout {
    pub object: usize,
    pub offset: u64,
    pub pitch: u64,
    pub width: u32,
    pub height: u32,
}
#[cfg(unix)]
#[derive(Debug)]
pub struct DmaBuf {
    width: u32,
    height: u32,
    fourcc: u32,
    objects: Vec<DmaObject>,
    planes: Vec<PlaneLayout>,
    acquire: Option<Arc<FenceFd>>,
}
#[cfg(unix)]
impl DmaBuf {
    /// # Safety
    /// Objects are real owned DMA-BUF exports. Layout/modifiers come from their
    /// original producer, and remain valid through all retained image leases.
    /// This never converts a guest fd number or opaque pointer into authority.
    pub unsafe fn exported(
        width: u32,
        height: u32,
        fourcc: u32,
        objects: Vec<DmaObject>,
        planes: Vec<PlaneLayout>,
        acquire: Option<Arc<FenceFd>>,
    ) -> io::Result<Self> {
        if width == 0
            || height == 0
            || objects.is_empty()
            || objects.len() > 4
            || planes.is_empty()
            || planes.len() > 4
            || acquire
                .as_ref()
                .is_some_and(|f| f.kind() != FenceKind::SyncFile)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        for plane in &planes {
            let object = objects
                .get(plane.object)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
            if plane.width == 0
                || plane.height == 0
                || plane.width > width
                || plane.height > height
                || plane.pitch == 0
                || plane.offset >= object.size
                || object.modifier == 0
                    && plane
                        .pitch
                        .checked_mul(plane.height as u64)
                        .and_then(|n| n.checked_add(plane.offset))
                        .is_none_or(|end| end > object.size)
            {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        }
        Ok(Self {
            width,
            height,
            fourcc,
            objects,
            planes,
            acquire,
        })
    }
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
    pub fn fourcc(&self) -> u32 {
        self.fourcc
    }
    pub fn objects(&self) -> &[DmaObject] {
        &self.objects
    }
    pub fn planes(&self) -> &[PlaneLayout] {
        &self.planes
    }
    pub fn acquire(&self) -> Option<&Arc<FenceFd>> {
        self.acquire.as_ref()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn typed_handles_never_turn_an_unavailable_image_into_metal() {
        assert!(NativeHandle::Empty.metal_texture().is_err());
        assert!(NativeHandle::MetalTexture(0).metal_texture().is_err());
    }
    #[test]
    fn owned_notification_fence_wakes_original_host_wait() {
        use std::{
            io::Write,
            os::unix::net::UnixStream,
            time::{Duration, Instant},
        };
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let fence = FenceFd::notification(reader.into());
        assert!(!fence.ready().unwrap());
        let mut wait = trames_shared::HostWait::new().unwrap();
        wait.begin();
        fence.interest(&mut wait).unwrap();
        wait.until(Instant::now() + Duration::from_secs(1));
        writer.write_all(b"ready").unwrap();
        wait.wait().unwrap();
        assert!(fence.ready().unwrap());
        assert_eq!(fence.kind(), FenceKind::Notification);
    }
}
