// SPDX-License-Identifier: GPL-3.0-or-later
//! Linear CPU/device-shareable image storage. This is not a fake DMA-BUF export.
use super::*;
#[derive(Clone, Default)]
pub struct Context;
struct Plane {
    info: ImageInfo,
    mapping: trames_memory::SharedMapping,
    cpu: Arc<crate::cpu::Plane>,
}
impl Context {
    pub fn allocate(&self, format: Format, width: u32, height: u32) -> io::Result<Arc<dyn Image>> {
        if width == 0 || height == 0 {
            return Err(io::Error::from_raw_os_error(22));
        }
        let pitch = (width as u64)
            .checked_mul(format.bytes() as u64)
            .and_then(|n| n.checked_next_multiple_of(64))
            .ok_or_else(|| io::Error::from_raw_os_error(75))?;
        let size = pitch
            .checked_mul(height as u64)
            .filter(|&n| n <= usize::MAX as u64)
            .ok_or_else(|| io::Error::from_raw_os_error(75))?;
        let mapping = trames_memory::SharedMapping::anonymous_file(
            size as usize,
            trames_memory::host_mapping_granule(),
        )?;
        let cpu =
            Arc::new(unsafe { crate::cpu::Plane::from_mapping(mapping.clone(), size as usize) });
        Ok(Arc::new(Plane {
            info: ImageInfo {
                width,
                height,
                format,
                pitch,
                size,
            },
            mapping,
            cpu,
        }))
    }
    pub fn display_texture(_: &dyn Image) -> io::Result<Arc<Texture>> {
        Err(io::Error::from_raw_os_error(95))
    }
    /// # Safety
    /// Unsupported on Linux; the Apple value is never dereferenced.
    pub unsafe fn pixel_buffer_plane(&self, _: usize, _: u32) -> io::Result<Arc<dyn Image>> {
        Err(io::Error::from_raw_os_error(95))
    }
}
// SAFETY: retained sealed file storage, original canonical page cache and byte
// guards. Importers receive an explicit FD geometry, never an opaque GPU pointer.
unsafe impl Image for Plane {
    fn info(&self) -> ImageInfo {
        self.info
    }
    fn shared_mapping(&self) -> Option<trames_memory::SharedMapping> {
        Some(self.mapping.clone())
    }
    fn cpu_pages(
        &self,
        offset: u64,
        length: u64,
    ) -> io::Result<Vec<Arc<dyn trames_memory::PageBacking>>> {
        self.cpu.pages(offset, length)
    }
    fn cpu_access(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linear_images_export_real_fd_pages_without_claiming_metal_or_dmabuf() {
        for format in [Format::Rgba8, Format::Bgra8, Format::R8, Format::Rg8] {
            let image = Context.allocate(format, 65, 37).unwrap();
            let info = image.info();
            assert_eq!(info.pitch % 64, 0);
            assert!(image.dma_buf().is_err());
            let mapping = image.shared_mapping().unwrap();
            assert!(mapping.file_descriptor().is_some());
            let length = info.size.next_multiple_of(trames_memory::PAGE_SIZE);
            let pages = image.cpu_pages(0, length).unwrap();
            let again = image.cpu_pages(0, length).unwrap();
            assert!(Arc::ptr_eq(
                &pages[0].shared_page().unwrap(),
                &again[0].shared_page().unwrap()
            ));
            assert!(unsafe { image.native_texture(NativeDevice::Metal(0)) }.is_err());
            pages[0].write(0, &[13, 37, 91, 255]).unwrap();
            drop(image);
            let mut out = [0; 4];
            again[0].read(0, &mut out).unwrap();
            assert_eq!(out, [13, 37, 91, 255]);
            assert_eq!(unsafe { mapping.pointer().read_volatile() }, 13);
        }
    }
}
