// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[cfg(target_vendor = "apple")]
mod apple {
    use super::*;
    use std::{collections::BTreeMap, ffi::c_void, sync::Mutex};
    unsafe extern "C" {
        fn trames_graphics_allocate(format: u32, width: u32, height: u32) -> *mut c_void;
        fn trames_graphics_plane(buffer: *mut c_void, plane: u32) -> *mut c_void;
        fn trames_graphics_image_free(image: *mut c_void);
        fn trames_graphics_info(image: *mut c_void, info: *mut u64) -> i32;
        fn trames_graphics_cache(device: *mut c_void) -> *mut c_void;
        fn trames_graphics_cache_free(cache: *mut c_void);
        fn trames_graphics_texture(image: *mut c_void, cache: *mut c_void) -> *mut c_void;
        fn trames_graphics_texture_handle(texture: *mut c_void) -> *mut c_void;
        fn trames_graphics_texture_free(texture: *mut c_void);
    }
    struct NativeImage(*mut c_void);
    // SAFETY: a uniquely retained CoreVideo buffer, with immutable plane metadata.
    // Metal and hardware producers retain the same buffer; their access ordering
    // follows the original API's fences and completion, not Rust byte references.
    unsafe impl Send for NativeImage {}
    unsafe impl Sync for NativeImage {}
    impl Drop for NativeImage {
        fn drop(&mut self) {
            unsafe { trames_graphics_image_free(self.0) }
        }
    }
    struct Cache(*mut c_void);
    // SAFETY: cache calls share its mutex; the native cache retains MTLDevice.
    unsafe impl Send for Cache {}
    impl Drop for Cache {
        fn drop(&mut self) {
            unsafe { trames_graphics_cache_free(self.0) }
        }
    }
    struct NativeTexture {
        raw: *mut c_void,
        _image: Arc<NativeImage>,
        _cache: Arc<Mutex<Cache>>,
    }
    // SAFETY: immutable CVMetalTexture plus retained image, cache and device.
    unsafe impl Send for NativeTexture {}
    unsafe impl Sync for NativeTexture {}
    impl Drop for NativeTexture {
        fn drop(&mut self) {
            unsafe { trames_graphics_texture_free(self.raw) }
        }
    }
    #[derive(Default)]
    struct Caches(Mutex<BTreeMap<usize, Arc<Mutex<Cache>>>>);
    #[derive(Clone, Default)]
    pub struct Context(Arc<Caches>);
    struct Plane {
        native: Arc<NativeImage>,
        info: ImageInfo,
        context: Context,
        textures: Mutex<BTreeMap<usize, Arc<Texture>>>,
    }
    impl Context {
        fn adopt(&self, raw: *mut c_void) -> io::Result<Arc<dyn Image>> {
            if raw.is_null() {
                return Err(io::Error::from_raw_os_error(95));
            }
            let native = Arc::new(NativeImage(raw));
            let mut values = [0; 5];
            if unsafe { trames_graphics_info(raw, values.as_mut_ptr()) } != 0 {
                return Err(io::Error::from_raw_os_error(95));
            }
            let format = Format::from_vk(values[2] as u32)
                .ok_or_else(|| io::Error::from_raw_os_error(95))?;
            let info = ImageInfo {
                width: values[0] as u32,
                height: values[1] as u32,
                format,
                pitch: values[3],
                size: values[4],
            };
            Ok(Arc::new(Plane {
                native,
                info,
                context: self.clone(),
                textures: Mutex::default(),
            }))
        }
        pub fn allocate(
            &self,
            format: Format,
            width: u32,
            height: u32,
        ) -> io::Result<Arc<dyn Image>> {
            if width == 0 || height == 0 {
                return Err(io::Error::from_raw_os_error(22));
            }
            self.adopt(unsafe { trames_graphics_allocate(format as u32, width, height) })
        }
        /// # Safety
        /// The pointer is a live CVPixelBufferRef during the call; native code
        /// retains it before returning. It is never interpreted as a guest address.
        pub unsafe fn pixel_buffer_plane(
            &self,
            buffer: usize,
            plane: u32,
        ) -> io::Result<Arc<dyn Image>> {
            self.adopt(unsafe { trames_graphics_plane(buffer as *mut c_void, plane) })
        }
    }
    // SAFETY: Plane owns its CoreVideo allocation and all produced texture leases.
    unsafe impl Image for Plane {
        fn info(&self) -> ImageInfo {
            self.info
        }
        unsafe fn metal_texture(&self, device: usize) -> io::Result<Arc<Texture>> {
            let mut textures = self.textures.lock().unwrap();
            if let Some(texture) = textures.get(&device) {
                return Ok(texture.clone());
            }
            let cache = {
                let mut caches = self.context.0 .0.lock().unwrap();
                if let Some(cache) = caches.get(&device) {
                    cache.clone()
                } else {
                    let raw = unsafe { trames_graphics_cache(device as *mut c_void) };
                    if raw.is_null() {
                        return Err(io::Error::from_raw_os_error(5));
                    }
                    let cache = Arc::new(Mutex::new(Cache(raw)));
                    caches.insert(device, cache.clone());
                    cache
                }
            };
            let raw = {
                let cache = cache.lock().unwrap();
                unsafe { trames_graphics_texture(self.native.0, cache.0) }
            };
            if raw.is_null() {
                return Err(io::Error::from_raw_os_error(5));
            }
            let handle = unsafe { trames_graphics_texture_handle(raw) } as usize;
            let owner = Arc::new(NativeTexture {
                raw,
                _image: self.native.clone(),
                _cache: cache,
            });
            let texture = Arc::new(unsafe { Texture::retained(handle, owner) });
            textures.insert(device, texture.clone());
            Ok(texture)
        }
    }
}
#[cfg(target_vendor = "apple")]
pub use apple::Context;
#[cfg(not(target_vendor = "apple"))]
#[derive(Clone, Default)]
pub struct Context;
#[cfg(not(target_vendor = "apple"))]
impl Context {
    pub fn allocate(&self, _: Format, _: u32, _: u32) -> io::Result<Arc<dyn Image>> {
        Err(io::Error::from_raw_os_error(95))
    }
    /// # Safety
    /// Unsupported on non-Apple hosts; never dereferences the supplied value.
    pub unsafe fn pixel_buffer_plane(&self, _: usize, _: u32) -> io::Result<Arc<dyn Image>> {
        Err(io::Error::from_raw_os_error(95))
    }
}
