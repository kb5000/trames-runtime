// SPDX-License-Identifier: GPL-3.0-or-later
//! Imported guest FD image planes, backed directly by retained native textures.
use super::*;
pub(super) const CAPABILITY: u64 = 8192;
#[derive(Clone, Copy)]
pub(super) struct ImageLayout {
    pub pitch: u64,
    pub offset: u64,
}
pub(super) enum Resource {
    Image(ImageLayout),
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    Memory {
        image: Arc<dyn trames_graphics::Image>,
        dedicated: u64,
    },
}
impl Backend {
    pub(super) fn native_image_types(&self) -> u32 {
        self.device.as_ref().unwrap().external_image_memory_types
    }
    pub(super) fn imported_requirements(&self, image: &Object) -> Option<vk::MemoryRequirements> {
        let extra = image.external.borrow();
        let Some(Resource::Image(layout)) = extra.as_deref() else {
            return None;
        };
        let shape = image.image.get()?;
        Some(vk::MemoryRequirements {
            size: layout.offset + layout.pitch * u64::from(shape.height),
            alignment: 1,
            memory_type_bits: self.native_image_types(),
        })
    }
    pub(super) fn import_image_memory(
        &mut self,
        m: &mut impl CpuMemory,
        a: [u64; 16],
    ) -> Result<()> {
        let dev = self.device.as_ref().unwrap();
        if dev.metal_device == 0
            || a[8] != 512
            || a[5] != 2
            || a[9] != 0
            || a[4] & !2 != 0
            || a[4] != 0 && dev.compute_features & compute::BUFFER_DEVICE_ADDRESS == 0
        {
            return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into());
        }
        let files = self
            .image_files
            .as_ref()
            .ok_or(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?
            .clone();
        let fd = u32::try_from(a[7] - 1).map_err(|_| vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
        let image = files
            .lookup(fd)
            .map_err(|_| vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
        let resource = self.object(a[6], Kind::Image)?;
        let requirements = self
            .imported_requirements(&resource)
            .ok_or(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
        if a[1] < requirements.size
            || a[1] > image.info().size
            || a[2] >= 32
            || requirements.memory_type_bits & (1 << (a[2] as u32)) == 0
        {
            return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into());
        }
        drop(resource);
        let id = self.put(
            Kind::Memory,
            0,
            vec![],
            a[1],
            vk::MemoryPropertyFlags::DEVICE_LOCAL.as_raw(),
        );
        let object = &self.objects[&id];
        object.state.set(a[2] as u8);
        object.allocation_flags.set(a[4] as u32);
        *object.external.borrow_mut() = Some(Box::new(Resource::Memory {
            image,
            dedicated: a[6],
        }));
        self.publish(m, a[3], id)?;
        files.close(fd);
        Ok(())
    }
    #[cfg(not(target_vendor = "apple"))]
    pub(super) fn bind_native_image(&mut self, _: u64, _: u64, _: u64) -> Result<()> {
        unsupported()
    }
    #[cfg(target_vendor = "apple")]
    pub(super) fn bind_native_image(
        &mut self,
        image_id: u64,
        memory_id: u64,
        offset: u64,
    ) -> Result<()> {
        let device = self.device.as_ref().unwrap().clone();
        let object = self.object(image_id, Kind::Image)?;
        let shape = object
            .image
            .get()
            .ok_or(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
        let memory = self.object(memory_id, Kind::Memory)?;
        let native = {
            let payload = memory.external.borrow();
            let Some(Resource::Memory { image, dedicated }) = payload.as_deref() else {
                return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into());
            };
            if *dedicated != image_id || offset != 0 || !object.deps.borrow().is_empty() {
                return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into());
            }
            image.clone()
        };
        let layout = {
            let extra = object.external.borrow();
            match extra.as_deref() {
                Some(Resource::Image(layout)) => *layout,
                _ => return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into()),
            }
        };
        let info = native.info();
        if info.width != shape.width
            || info.height != shape.height
            || info.format as i32 != shape.format.as_raw()
            || layout.pitch != info.pitch
            || layout.offset != 0
        {
            return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into());
        }
        // A conforming non-sparse image is bound before views or commands may
        // retain it. This leaves the registry's one Rc when replacing the
        // unbound placeholder, with no interior mutation of live native handles.
        if Rc::strong_count(&object) != 2 || Rc::weak_count(&object) != 0 {
            return invalid();
        }
        #[cfg(target_vendor = "apple")]
        let raw = {
            // SAFETY: Device owns this MTLDevice throughout the call; the image
            // creates an independently retained texture/storage/device lease.
            let texture = unsafe { native.metal_texture(device.metal_device) }
                .map_err(|_| vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
            let mut import = vk::ImportMetalTextureInfoEXT::default()
                .plane(vk::ImageAspectFlags::COLOR)
                .mtl_texture(texture.handle() as _);
            let mut list = vk::ImageFormatListCreateInfo::default();
            let mut create = vk::ImageCreateInfo::default()
                .push_next(&mut import)
                .image_type(vk::ImageType::TYPE_2D)
                .format(shape.format)
                .extent(vk::Extent3D {
                    width: shape.width,
                    height: shape.height,
                    depth: 1,
                })
                .mip_levels(1)
                .array_layers(1)
                .samples(vk::SampleCountFlags::TYPE_1)
                .tiling(vk::ImageTiling::OPTIMAL)
                .usage(vk::ImageUsageFlags::from_raw(object.flags))
                .flags(vk::ImageCreateFlags::from_raw(object.image_flags.get()));
            // Mutable color views retain their ordinary Vulkan creation flags.
            if object.image_flags.get() & vk::ImageCreateFlags::MUTABLE_FORMAT.as_raw() != 0 {
                create = create.push_next(&mut list);
            }
            unsafe { device.native.create_image(&create, None) }?
        };
        drop(object);
        let object = Rc::get_mut(self.objects.get_mut(&image_id).unwrap())
            .expect("unbound imported image has one owner");
        unsafe {
            device
                .native
                .destroy_image(vk::Image::from_raw(object.raw), None)
        };
        object.raw = raw.as_raw();
        object.memory_binding.set(Some(coherent::Binding {
            memory: memory_id,
            offset: 0,
            size: memory.size,
        }));
        object.deps.get_mut().push(memory);
        Ok(())
    }
    pub(super) fn image_fd_call(
        &self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        match op {
            240 => return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into()), // import-only profile
            241 => {
                if a[2] != 512 {
                    return Err(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE.into());
                }
                let files = self
                    .image_files
                    .as_ref()
                    .ok_or(vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
                files
                    .lookup(a[1] as u32)
                    .map_err(|_| vk::Result::ERROR_INVALID_EXTERNAL_HANDLE)?;
                write(m, a[3], &self.native_image_types().to_le_bytes())?;
            }
            242 => {
                let image = self.object(a[1], Kind::Image)?;
                if !matches!(image.external.borrow().as_deref(), Some(Resource::Image(_))) {
                    return invalid();
                }
                write(m, a[2], &0u64.to_le_bytes())?;
            }
            _ => return unsupported(),
        }
        Ok(())
    }
}
