// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[cfg(target_vendor = "apple")]
mod apple {
    use super::*;
    use std::{collections::BTreeMap, ffi::c_void, sync::Mutex};
    unsafe extern "C" {
        fn trames_graphics_default_device() -> *mut c_void;
        fn trames_graphics_allocate(format: u32, width: u32, height: u32) -> *mut c_void;
        fn trames_graphics_plane(buffer: *mut c_void, plane: u32) -> *mut c_void;
        fn trames_graphics_image_free(image: *mut c_void);
        fn trames_graphics_info(image: *mut c_void, info: *mut u64) -> i32;
        fn trames_graphics_cache(device: *mut c_void) -> *mut c_void;
        fn trames_graphics_cache_free(cache: *mut c_void);
        fn trames_graphics_texture(image: *mut c_void, cache: *mut c_void) -> *mut c_void;
        fn trames_graphics_texture_handle(texture: *mut c_void) -> *mut c_void;
        fn trames_graphics_texture_free(texture: *mut c_void);
        fn trames_graphics_cpu(image: *mut c_void, values: *mut u64) -> i32;
        fn trames_graphics_cpu_access(image: *mut c_void, begin: bool) -> i32;
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
        cpu: std::sync::OnceLock<Arc<crate::cpu::Plane>>,
    }
    impl Context {
        pub fn display_texture(image: &dyn Image) -> io::Result<Arc<Texture>> {
            let device = unsafe { trames_graphics_default_device() } as usize;
            if device == 0 {
                return Err(io::Error::from_raw_os_error(95));
            }
            // SAFETY: native code retains its default device for process life.
            unsafe { image.metal_texture(device) }
        }
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
                cpu: std::sync::OnceLock::new(),
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
        fn cpu_access(&self, begin: bool) -> io::Result<()> {
            if unsafe { trames_graphics_cpu_access(self.native.0, begin) } == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(5))
            }
        }
        fn cpu_pages(
            &self,
            offset: u64,
            length: u64,
        ) -> io::Result<Vec<Arc<dyn trames_memory::PageBacking>>> {
            if self.cpu.get().is_none() {
                let mut values = [0; 3];
                if unsafe { trames_graphics_cpu(self.native.0, values.as_mut_ptr()) } != 0 {
                    return Err(io::Error::from_raw_os_error(5));
                }
                let [address, length, offset] = values.map(|v| v as usize);
                let size = self.info.size as usize;
                if !offset.is_multiple_of(trames_memory::PAGE_SIZE as usize)
                    || offset
                        .checked_add(
                            size.div_ceil(trames_memory::PAGE_SIZE as usize)
                                * trames_memory::PAGE_SIZE as usize,
                        )
                        .is_none_or(|end| end > length)
                {
                    return Err(io::Error::from_raw_os_error(95));
                }
                // SAFETY: the original IOSurface owns this stationary initialized
                // allocation, whose bounds and plane offset are checked above.
                let mapping = unsafe {
                    crate::cpu::Plane::new(address, length, offset, size, self.native.clone())
                };
                let _ = self.cpu.set(Arc::new(mapping));
            }
            self.cpu.get().unwrap().pages(offset, length)
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
    pub fn display_texture(_: &dyn Image) -> io::Result<Arc<Texture>> {
        Err(io::Error::from_raw_os_error(95))
    }
    pub fn allocate(&self, _: Format, _: u32, _: u32) -> io::Result<Arc<dyn Image>> {
        Err(io::Error::from_raw_os_error(95))
    }
    /// # Safety
    /// Unsupported on non-Apple hosts; never dereferences the supplied value.
    pub unsafe fn pixel_buffer_plane(&self, _: usize, _: u32) -> io::Result<Arc<dyn Image>> {
        Err(io::Error::from_raw_os_error(95))
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    #[test]
    fn native_color_planes_share_canonical_cpu_pages_and_metal_storage() {
        for format in [Format::Rgba8, Format::Bgra8, Format::R8] {
            let image = Context::default().allocate(format, 65, 37).unwrap();
            let info = image.info();
            assert_eq!((info.width, info.height, info.format), (65, 37, format));
            assert!(info.pitch >= 65 * format.bytes() as u64);
            let length = info.size.div_ceil(trames_memory::PAGE_SIZE) * trames_memory::PAGE_SIZE;
            let first = image.cpu_pages(0, length).unwrap();
            let second = image.cpu_pages(0, length).unwrap();
            let a = first[0].shared_page().unwrap();
            let b = second[0].shared_page().unwrap();
            assert!(Arc::ptr_eq(&a, &b));
            image.cpu_access(true).unwrap();
            first[0].write(0, &[13, 37, 91, 255]).unwrap();
            let mut bytes = [0; 4];
            second[0].read(0, &mut bytes).unwrap();
            assert_eq!(bytes, [13, 37, 91, 255]);
            image.cpu_access(false).unwrap();
            let texture = Context::display_texture(image.as_ref()).unwrap();
            assert_ne!(texture.handle(), 0);
            drop(image);
            let mut bytes = [0; 4];
            first[0].read(0, &mut bytes).unwrap();
            assert_eq!(bytes, [13, 37, 91, 255]);
            drop(texture);
        }
    }
}
