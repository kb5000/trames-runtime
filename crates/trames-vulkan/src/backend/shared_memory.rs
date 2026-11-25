// SPDX-License-Identifier: GPL-3.0-or-later
//! Stable caller-owned buffer imports and original native allocation mappings.
//! Generic Vulkan memory stays driver-owned so image/buffer aliases keep their
//! original layout and storage. Guest views retain the actual native owner.
use super::*;
use std::alloc::Layout;
#[cfg(not(target_os = "linux"))]
use std::alloc::{alloc_zeroed, dealloc};
pub(super) const MAP_SHARED: u64 = 0x5348_4152_4544;

/// Only generic coherent driver allocations can acquire implementation padding.
/// Guest binding/map bounds remain the original request; native byte ownership
/// and its budget charge include the complete mapping granules. Dedicated and
/// external allocations retain their original native allocation contract.
pub(super) fn native_size(
    size: u64,
    flags: vk::MemoryPropertyFlags,
    dedicated: bool,
) -> Result<u64> {
    if !dedicated
        && flags.contains(
            vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT,
        )
    {
        size.checked_next_multiple_of(trames_memory::host_mapping_granule() as u64)
            .ok_or_else(|| vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into())
    } else {
        Ok(size)
    }
}

pub(super) struct Allocation {
    pub(super) revision: Arc<AtomicU64>,
    pointer: usize,
    length: usize,
    storage: Storage,
    budget: crate::Budget,
}
enum Storage {
    #[cfg(not(target_os = "linux"))]
    Host(Layout),
    #[cfg(target_os = "linux")]
    File(trames_memory::SharedMapping),
    Native {
        memory: vk::DeviceMemory,
        device: Arc<Device>,
    },
}
impl Allocation {
    pub(super) fn new(size: u64, alignment: u64, budget: &crate::Budget) -> Result<Arc<Self>> {
        let align = usize::try_from(alignment)
            .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?
            .max(trames_memory::host_mapping_granule());
        let size = usize::try_from(size)
            .ok()
            .and_then(|n| n.checked_next_multiple_of(align))
            .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        let _layout = Layout::from_size_align(size, align)
            .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        if !budget.reserve(size as u64) {
            return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
        }
        #[cfg(target_os = "linux")]
        {
            let mapping = match trames_memory::SharedMapping::anonymous_file(size, align) {
                Ok(m) => m,
                Err(_) => {
                    budget.release(size as u64);
                    return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
                }
            };
            Ok(Arc::new(Self {
                revision: Arc::default(),
                pointer: mapping.allocation_pointer() as usize,
                length: mapping.allocation_len(),
                storage: Storage::File(mapping),
                budget: budget.clone(),
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: valid bounded native allocation; initialized padding remains owned.
            let pointer = unsafe { alloc_zeroed(_layout) } as usize;
            if pointer == 0 {
                budget.release(size as u64);
                return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
            }
            Ok(Arc::new(Self {
                revision: Arc::default(),
                pointer,
                length: _layout.size(),
                storage: Storage::Host(_layout),
                budget: budget.clone(),
            }))
        }
    }
    /// Transfer the original allocation/mapping and its existing budget charge.
    ///
    /// # Safety
    /// The whole allocation is mapped at pointer, initialized foreign storage,
    /// and its complete page granules are owned exclusively by this allocation.
    /// The caller immediately publishes this owner, then never unmaps/frees the
    /// native memory itself. The retained original device outlives that free.
    pub(super) unsafe fn native(
        pointer: *mut u8,
        size: usize,
        memory: vk::DeviceMemory,
        device: Arc<Device>,
        budget: &crate::Budget,
    ) -> Arc<Self> {
        Arc::new(Self {
            revision: Arc::default(),
            pointer: pointer as usize,
            length: size,
            storage: Storage::Native { memory, device },
            budget: budget.clone(),
        })
    }
    pub(super) fn owns_native(&self) -> bool {
        matches!(self.storage, Storage::Native { .. })
    }
    pub(super) fn importable(&self, native_pointers: bool) -> bool {
        #[cfg(target_os = "linux")]
        if matches!(self.storage, Storage::File(_)) {
            return true;
        }
        native_pointers
    }
    pub(super) fn pointer(&self) -> *mut u8 {
        self.pointer as *mut u8
    }
    pub(super) fn len(&self) -> usize {
        self.length
    }
    pub(super) fn mapping(self: &Arc<Self>, offset: usize) -> Option<trames_memory::SharedMapping> {
        #[cfg(target_os = "linux")]
        if let Storage::File(mapping) = &self.storage {
            return mapping
                .clone()
                .retaining(self.clone())
                .with_external_revision(self.revision.clone())
                .with_offset(offset);
        }
        // SAFETY: the allocation is initialized stable host storage. Both native
        // Vulkan objects and all guest mappings retain its Arc. Vulkan keeps its
        // original application-owned CPU/GPU synchronization requirements.
        unsafe {
            trames_memory::SharedMapping::from_allocation(self.pointer(), self.len(), self.clone())
        }
        .with_external_revision(self.revision.clone())
        .with_offset(offset)
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: final guest/native owner releases its exact original storage.
        // Native mappings keep both device and instance alive until this point.
        unsafe {
            match &self.storage {
                #[cfg(not(target_os = "linux"))]
                Storage::Host(layout) => dealloc(self.pointer(), *layout),
                #[cfg(target_os = "linux")]
                Storage::File(_) => {}
                Storage::Native { memory, device } => {
                    device.native.unmap_memory(*memory);
                    device.native.free_memory(*memory, None);
                }
            }
        }
        self.budget.release(self.length as u64);
    }
}

pub(super) fn host_buffer_importable(dev: &Device, usage: vk::BufferUsageFlags) -> bool {
    if dev.host_alignment == 0 {
        return false;
    }
    let info = vk::PhysicalDeviceExternalBufferInfo::default()
        .usage(usage)
        .handle_type(vk::ExternalMemoryHandleTypeFlags::HOST_ALLOCATION_EXT);
    let mut props = vk::ExternalBufferProperties::default();
    unsafe {
        dev.instance
            .native
            .get_physical_device_external_buffer_properties(dev.physical, &info, &mut props)
    };
    props
        .external_memory_properties
        .external_memory_features
        .contains(vk::ExternalMemoryFeatureFlags::IMPORTABLE)
        && props
            .external_memory_properties
            .compatible_handle_types
            .contains(vk::ExternalMemoryHandleTypeFlags::HOST_ALLOCATION_EXT)
}

impl Backend {
    pub(super) fn allocate_shared(
        &self,
        dev: &Device,
        size: u64,
        ty: u32,
        flags: u32,
        mut dedicated: vk::MemoryDedicatedAllocateInfo<'_>,
    ) -> Option<Result<(vk::DeviceMemory, Arc<Allocation>)>> {
        // Only an explicit dedicated-buffer contract excludes future image
        // bindings. Generic allocations must retain native image/buffer aliases.
        if dev.host_alignment == 0 || dedicated.buffer.is_null() {
            return None;
        }
        Some((|| {
            let owner = Allocation::new(size, dev.host_alignment, &self.budget)?;
            let api =
                ash::ext::external_memory_host::Device::new(&dev.instance.native, &dev.native);
            let mut props = vk::MemoryHostPointerPropertiesEXT::default();
            unsafe {
                (api.fp().get_memory_host_pointer_properties_ext)(
                    dev.native.handle(),
                    vk::ExternalMemoryHandleTypeFlags::HOST_ALLOCATION_EXT,
                    owner.pointer().cast(),
                    &mut props,
                )
                .result()
            }?;
            if props.memory_type_bits & (1 << ty) == 0 {
                return unsupported();
            }
            let mut import = vk::ImportMemoryHostPointerInfoEXT::default()
                .handle_type(vk::ExternalMemoryHandleTypeFlags::HOST_ALLOCATION_EXT)
                .host_pointer(owner.pointer().cast());
            let mut allocation_flags = vk::MemoryAllocateFlagsInfo::default()
                .flags(vk::MemoryAllocateFlags::from_raw(flags));
            let mut info = vk::MemoryAllocateInfo::default()
                .allocation_size(owner.len() as u64)
                .memory_type_index(ty)
                .push_next(&mut import);
            if flags != 0 {
                info = info.push_next(&mut allocation_flags);
            }
            if !dedicated.buffer.is_null() || !dedicated.image.is_null() {
                info = info.push_next(&mut dedicated);
            }
            let raw = unsafe { dev.native.allocate_memory(&info, None) }?;
            Ok((raw, owner))
        })())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generic_padding_owns_whole_granules_without_changing_other_contracts() {
        let flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
        let granule = trames_memory::host_mapping_granule() as u64;
        assert_eq!(native_size(granule, flags, false).unwrap(), granule);
        assert_eq!(native_size(granule + 1, flags, false).unwrap(), granule * 2);
        assert_eq!(native_size(granule + 1, flags, true).unwrap(), granule + 1);
        assert_eq!(
            native_size(granule + 1, vk::MemoryPropertyFlags::HOST_VISIBLE, false).unwrap(),
            granule + 1
        );
        assert!(matches!(
            native_size(u64::MAX, flags, false),
            Err(Failure::Vk(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY))
        ));
    }
}
