// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned native image planes shared by video, Vulkan and guest FD resources.
use std::{io, sync::Arc};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Format {
    R8 = 9,
    Rg8 = 16,
    Rgba8 = 37,
    Bgra8 = 44,
}
impl Format {
    pub fn bytes(self) -> u32 {
        match self {
            Self::R8 => 1,
            Self::Rg8 => 2,
            _ => 4,
        }
    }
    pub fn fourcc(self) -> u32 {
        u32::from_le_bytes(match self {
            Self::R8 => *b"R8  ",
            Self::Rg8 => *b"GR88",
            Self::Rgba8 => *b"AB24",
            Self::Bgra8 => *b"AR24",
        })
    }
    pub fn from_vk(value: u32) -> Option<Self> {
        Some(match value {
            9 => Self::R8,
            16 => Self::Rg8,
            37 => Self::Rgba8,
            44 => Self::Bgra8,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ImageInfo {
    pub width: u32,
    pub height: u32,
    pub format: Format,
    pub pitch: u64,
    pub size: u64,
}
pub struct Texture {
    handle: usize,
    _owner: Arc<dyn Send + Sync>,
}
impl Texture {
    /// # Safety
    /// `handle` is a live MTLTexture. `owner` retains its storage and device;
    /// both outlive every GPU use for which this Texture is retained.
    pub unsafe fn retained(handle: usize, owner: Arc<dyn Send + Sync>) -> Self {
        Self {
            handle,
            _owner: owner,
        }
    }
    pub fn handle(&self) -> usize {
        self.handle
    }
}
/// # Safety
/// Implementations own all native storage. Info describes the actual row-linear
/// plane, and textures alias that storage on the supplied retained Metal device.
/// No guest pointer or descriptor-table borrow may be retained by an Image.
pub unsafe trait Image: Send + Sync {
    fn info(&self) -> ImageInfo;
    /// # Safety
    /// `device` is a live id<MTLDevice> for the duration of this call.
    unsafe fn metal_texture(&self, device: usize) -> io::Result<Arc<Texture>>;
}
/// Real per-caller files_struct authority, supplied only for native FD operations.
pub trait ImageFds: Send + Sync {
    fn lookup(&self, fd: u32) -> io::Result<Arc<dyn Image>>;
    fn insert(&self, image: Arc<dyn Image>) -> io::Result<u32>;
    fn close(&self, fd: u32);
}
mod native;
pub use native::Context;
