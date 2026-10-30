// SPDX-License-Identifier: GPL-3.0-or-later
//! Stable host-visible allocations imported by both the driver and guest MMU.
use super::*;
use std::alloc::{alloc_zeroed, dealloc, Layout};
pub(super) const MAP_SHARED: u64 = 0x5348_4152_4544;

pub(super) struct Allocation {
    pub(super) revision: Arc<AtomicU64>,
    pointer: usize,
    layout: Layout,
    budget: crate::Budget,
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
        let layout = Layout::from_size_align(size, align)
            .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        if !budget.reserve(size as u64) {
            return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
        }
        // SAFETY: a valid bounded layout; zero initialization supplies every
        // exported padding page as well as the guest-visible allocation bytes.
        let pointer = unsafe { alloc_zeroed(layout) } as usize;
        if pointer == 0 {
            budget.release(size as u64);
            return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
        }
        Ok(Arc::new(Self {
            revision: Arc::default(),
            pointer,
            layout,
            budget: budget.clone(),
        }))
    }
    pub(super) fn pointer(&self) -> *mut u8 {
        self.pointer as *mut u8
    }
    pub(super) fn len(&self) -> usize {
        self.layout.size()
    }
    pub(super) fn mapping(self: &Arc<Self>, offset: usize) -> Option<trames_memory::SharedMapping> {
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
        // SAFETY: final native/mapping owner releases the exact original layout.
        unsafe { dealloc(self.pointer(), self.layout) };
        self.budget.release(self.layout.size() as u64);
    }
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
        if dev.host_alignment == 0 {
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
