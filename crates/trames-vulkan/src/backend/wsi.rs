// SPDX-License-Identifier: GPL-3.0-or-later
//! Standard guest display WSI over a native-only, retained Metal target.
use super::*;
use crate::display::Target;

pub(super) struct Surface {
    instance: Arc<Instance>,
    target: Arc<Target>,
    raw: vk::SurfaceKHR,
    owner: u64,
}
impl Drop for Surface {
    fn drop(&mut self) {
        unsafe {
            ash::khr::surface::Instance::new(&self.instance._entry, &self.instance.native)
                .destroy_surface(self.raw, None);
        }
        let _ =
            self.target
                .owner
                .compare_exchange(self.owner, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}
pub(super) struct Swapchain {
    device: Arc<Device>,
    surface: Rc<Surface>,
    raw: vk::SwapchainKHR,
    // Current acquisition/present objects survive native swapchain teardown.
    // Previous presentation objects move into an acquisition-fence submission:
    // acquire may return before that image's previous presentation completes.
    retained: RefCell<BTreeMap<u32, Vec<Rc<Object>>>>,
    budget: crate::Budget,
    bytes: u64,
}
impl Drop for Swapchain {
    fn drop(&mut self) {
        unsafe {
            let _ = self.device.native.device_wait_idle();
            ash::khr::swapchain::Device::new(&self.device.instance.native, &self.device.native)
                .destroy_swapchain(self.raw, None);
        }
        self.budget.release(self.bytes);
    }
}
struct Chain {
    native: Rc<Swapchain>,
    images: Vec<u64>,
    acquired: Vec<bool>,
    retired: bool,
}
#[derive(Default)]
pub(super) struct Wsi {
    pub surfaces: BTreeMap<u64, Rc<Surface>>,
    swapchains: BTreeMap<u64, Chain>,
    pub device_enabled: bool,
}
impl Wsi {
    pub(super) fn clear_device(&mut self) {
        self.swapchains.clear();
        self.device_enabled = false;
    }
}
impl Backend {
    fn live_surface(&self, id: u64) -> Result<Rc<Surface>> {
        let surface = self
            .wsi
            .surfaces
            .get(&id)
            .cloned()
            .ok_or(Failure::Vk(vk::Result::ERROR_SURFACE_LOST_KHR))?;
        if !self.display.current(&surface.target) {
            return Err(vk::Result::ERROR_SURFACE_LOST_KHR.into());
        }
        Ok(surface)
    }
    pub(super) fn wsi_query(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let instance = self
            .instance
            .clone()
            .ok_or(Failure::Vk(vk::Result::ERROR_INITIALIZATION_FAILED))?;
        if !self.wsi_enabled {
            return Err(vk::Result::ERROR_EXTENSION_NOT_PRESENT.into());
        }
        if a[0]
            != if matches!(op, 81 | 82) {
                self.instance_id
            } else {
                self.physical_id
            }
        {
            return invalid();
        }
        if op == 80 {
            let (w, h, _) = self.display.info();
            return write_words(m, a[1], &[u64::from(w != 0), w as u64, h as u64], 24);
        }
        if op == 81 {
            self.room(self.wsi.surfaces.len() + 1)?;
            output(m, a[1], 8)?;
            let target = self
                .display
                .target()
                .ok_or(Failure::Vk(vk::Result::ERROR_SURFACE_LOST_KHR))?;
            let owner = self.id();
            target
                .owner
                .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| Failure::Vk(vk::Result::ERROR_NATIVE_WINDOW_IN_USE_KHR))?;
            let info = vk::MetalSurfaceCreateInfoEXT::default().layer(target.layer as *const _);
            let raw = match unsafe {
                ash::ext::metal_surface::Instance::new(&instance._entry, &instance.native)
                    .create_metal_surface(&info, None)
            } {
                Ok(raw) => raw,
                Err(e) => {
                    target.owner.store(0, Ordering::Release);
                    return Err(e.into());
                }
            };
            self.wsi.surfaces.insert(
                owner,
                Rc::new(Surface {
                    instance,
                    target,
                    raw,
                    owner,
                }),
            );
            if let Err(e) = write(m, a[1], &owner.to_le_bytes()) {
                self.wsi.surfaces.remove(&owner);
                return Err(e);
            }
            return Ok(());
        }
        if op == 82 {
            if self.wsi.surfaces.remove(&a[1]).is_none() {
                return invalid();
            }
            return Ok(());
        }
        let surface = self.live_surface(a[1])?;
        let loader = ash::khr::surface::Instance::new(&instance._entry, &instance.native);
        match op {
            83 => {
                let families = unsafe {
                    instance
                        .native
                        .get_physical_device_queue_family_properties(self.physical)
                };
                if a[2] >= families.len() as u64 {
                    return invalid();
                }
                let supported = unsafe {
                    loader.get_physical_device_surface_support(
                        self.physical,
                        a[2] as u32,
                        surface.raw,
                    )
                }?;
                write(m, a[3], &u32::from(supported).to_le_bytes())?;
            }
            84 => {
                let c = unsafe {
                    loader.get_physical_device_surface_capabilities(self.physical, surface.raw)
                }?;
                let w = surface.target.width;
                let h = surface.target.height;
                if c.current_extent.width != u32::MAX
                    && c.current_extent
                        != (vk::Extent2D {
                            width: w,
                            height: h,
                        })
                {
                    return Err(vk::Result::ERROR_OUT_OF_DATE_KHR.into());
                }
                if c.min_image_count > 4
                    || !c
                        .supported_transforms
                        .contains(vk::SurfaceTransformFlagsKHR::IDENTITY)
                    || !c
                        .supported_composite_alpha
                        .contains(vk::CompositeAlphaFlagsKHR::OPAQUE)
                    || !c
                        .supported_usage_flags
                        .contains(vk::ImageUsageFlags::COLOR_ATTACHMENT)
                {
                    return unsupported();
                }
                let values = [
                    c.min_image_count,
                    c.max_image_count.min(4),
                    w,
                    h,
                    w,
                    h,
                    w,
                    h,
                    1,
                    vk::SurfaceTransformFlagsKHR::IDENTITY.as_raw(),
                    vk::SurfaceTransformFlagsKHR::IDENTITY.as_raw(),
                    vk::CompositeAlphaFlagsKHR::OPAQUE.as_raw(),
                    c.supported_usage_flags.as_raw() & 0x13,
                ];
                let values: Vec<u32> = values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| if i == 1 && v == 0 { 4 } else { v })
                    .collect();
                write(
                    m,
                    a[2],
                    &values
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )?;
            }
            85 | 86 => {
                let bytes = if op == 85 {
                    let formats = unsafe {
                        loader.get_physical_device_surface_formats(self.physical, surface.raw)
                    }?;
                    if !formats.iter().any(|x| {
                        x.format == vk::Format::B8G8R8A8_UNORM
                            && x.color_space == vk::ColorSpaceKHR::SRGB_NONLINEAR
                    }) {
                        return unsupported();
                    }
                    [44u32.to_le_bytes(), 0u32.to_le_bytes()].concat()
                } else {
                    let modes = unsafe {
                        loader.get_physical_device_surface_present_modes(self.physical, surface.raw)
                    }?;
                    if !modes.contains(&vk::PresentModeKHR::FIFO) {
                        return unsupported();
                    }
                    2u32.to_le_bytes().to_vec()
                };
                let capacity = read32(m, a[2])?;
                output(m, a[2], 4)?;
                if a[3] != 0 && capacity != 0 {
                    write(m, a[3], &bytes)?;
                }
                write(
                    m,
                    a[2],
                    &u32::from(a[3] == 0 || capacity != 0).to_le_bytes(),
                )?;
                if a[3] != 0 && capacity == 0 {
                    return Err(vk::Result::INCOMPLETE.into());
                }
            }
            _ => return unsupported(),
        }
        Ok(())
    }
    pub(super) fn wsi_device(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        if !self.wsi.device_enabled {
            return Err(vk::Result::ERROR_EXTENSION_NOT_PRESENT.into());
        }
        if op == 87 && self.wayland.surfaces.contains_key(&a[1])
            || (88..=91).contains(&op) && self.wayland.has_chain(if op == 91 { a[2] } else { a[1] })
        {
            return self.wayland_device(m, op, a);
        }
        let device = self.device(a[0])?;
        let loader = ash::khr::swapchain::Device::new(&device.instance.native, &device.native);
        match op {
            87 => {
                output(m, a[10], 8)?;
                let surface = self.live_surface(a[1])?;
                let caps = unsafe {
                    ash::khr::surface::Instance::new(
                        &device.instance._entry,
                        &device.instance.native,
                    )
                    .get_physical_device_surface_capabilities(self.physical, surface.raw)
                }?;
                if a[2] < caps.min_image_count as u64
                    || a[2] > 4
                    || caps.max_image_count != 0 && a[2] > caps.max_image_count as u64
                    || a[3] != 44
                    || a[4] != 0
                    || a[5] != surface.target.width as u64
                    || a[6] != surface.target.height as u64
                    || a[7] & !0x13 != 0
                    || a[7] & 16 == 0
                    || a[7] & !(caps.supported_usage_flags.as_raw() as u64) != 0
                    || a[9] != 0
                    || a[11] > 1
                {
                    return unsupported();
                }
                let old = if a[8] == 0 {
                    vk::SwapchainKHR::null()
                } else {
                    let old = self
                        .wsi
                        .swapchains
                        .get(&a[8])
                        .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_DATE_KHR))?;
                    if !Rc::ptr_eq(&old.native.surface, &surface) {
                        return invalid();
                    }
                    old.native.raw
                };
                self.room(4 + self.wsi.surfaces.len() + self.wsi.swapchains.len())?;
                // Conservative reservation for up to four native scanout images.
                let bytes = a[5] * a[6] * 4 * 4;
                if !self.budget.reserve(bytes) {
                    return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
                }
                let info = vk::SwapchainCreateInfoKHR::default()
                    .surface(surface.raw)
                    .min_image_count(a[2] as u32)
                    .image_format(vk::Format::B8G8R8A8_UNORM)
                    .image_color_space(vk::ColorSpaceKHR::SRGB_NONLINEAR)
                    .image_extent(vk::Extent2D {
                        width: a[5] as u32,
                        height: a[6] as u32,
                    })
                    .image_array_layers(1)
                    .image_usage(vk::ImageUsageFlags::from_raw(a[7] as u32))
                    .image_sharing_mode(vk::SharingMode::EXCLUSIVE)
                    .pre_transform(vk::SurfaceTransformFlagsKHR::IDENTITY)
                    .composite_alpha(vk::CompositeAlphaFlagsKHR::OPAQUE)
                    .present_mode(vk::PresentModeKHR::FIFO)
                    .clipped(a[11] != 0)
                    .old_swapchain(old);
                let raw = match unsafe { loader.create_swapchain(&info, None) } {
                    Ok(x) => x,
                    Err(e) => {
                        self.budget.release(bytes);
                        return Err(e.into());
                    }
                };
                if a[8] != 0 {
                    self.wsi.swapchains.get_mut(&a[8]).unwrap().retired = true;
                }
                let native = Rc::new(Swapchain {
                    device,
                    surface,
                    raw,
                    retained: RefCell::new(BTreeMap::new()),
                    budget: self.budget.clone(),
                    bytes,
                });
                let images = unsafe { loader.get_swapchain_images(raw) }?;
                if images.len() > 4 {
                    return unsupported();
                }
                let mut ids = Vec::new();
                for image in images {
                    let id = self.put(Kind::SwapchainImage, image.as_raw(), vec![], 0, a[7] as u32);
                    let object = &self.objects[&id];
                    *object.swapchain.borrow_mut() = Some(native.clone());
                    object.image.set(Some(ImageShape::d2(
                        a[5] as u32,
                        a[6] as u32,
                        vk::Format::B8G8R8A8_UNORM,
                    )));
                    ids.push(id);
                }
                let id = self.id();
                let count = ids.len();
                self.wsi.swapchains.insert(
                    id,
                    Chain {
                        native,
                        images: ids,
                        acquired: vec![false; count],
                        retired: false,
                    },
                );
                if let Err(e) = write(m, a[10], &id.to_le_bytes()) {
                    self.drop_chain(id);
                    return Err(e);
                }
            }
            88 => {
                if !self.wsi.swapchains.contains_key(&a[1]) {
                    return invalid();
                }
                self.drop_chain(a[1]);
            }
            89 => {
                let chain = self
                    .wsi
                    .swapchains
                    .get(&a[1])
                    .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_DATE_KHR))?;
                let capacity = read32(m, a[2])? as usize;
                output(m, a[2], 4)?;
                let count = if a[3] == 0 {
                    chain.images.len()
                } else {
                    capacity.min(chain.images.len())
                };
                if a[3] != 0 {
                    write_words(m, a[3], &chain.images[..count], count * 8)?;
                }
                write(m, a[2], &(count as u32).to_le_bytes())?;
                if a[3] != 0 && count < chain.images.len() {
                    return Err(vk::Result::INCOMPLETE.into());
                }
            }
            90 => {
                output(m, a[4], 4)?;
                let chain = self
                    .wsi
                    .swapchains
                    .get_mut(&a[1])
                    .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_DATE_KHR))?;
                if chain.retired {
                    return Err(vk::Result::ERROR_OUT_OF_DATE_KHR.into());
                }
                if chain.acquired.iter().all(|acquired| *acquired) {
                    return Err(vk::Result::NOT_READY.into());
                }
                if !self.display.current(&chain.native.surface.target) {
                    return Err(vk::Result::ERROR_SURFACE_LOST_KHR.into());
                }
                // Resolve objects before taking mutable chain access below.
                let semaphore = if a[2] == 0 {
                    None
                } else {
                    Some({
                        let semaphore = self.object(a[2], Kind::Semaphore)?;
                        if semaphore.flags != 0 {
                            return invalid();
                        }
                        semaphore
                    })
                };
                let fence = if a[3] == 0 {
                    None
                } else {
                    Some(self.object(a[3], Kind::Fence)?)
                };
                if semaphore.as_ref().is_some_and(|s| s.state.get() != 0)
                    || semaphore.is_none() && fence.is_none()
                {
                    return invalid();
                }
                if let Some(f) = &fence {
                    if f.acquisition.borrow().is_some()
                        || unsafe { device.native.get_fence_status(vk::Fence::from_raw(f.raw)) }?
                        || self.submissions.iter().any(|s| Rc::ptr_eq(&s.fence, f))
                    {
                        return invalid();
                    }
                }
                // A successful acquire can precede availability (including in
                // original MoltenVK). Only its fence completion proves that old
                // present waits are finished. Never free them just on API return.
                // A guest fence may be reset as soon as acquisition is ready,
                // while MoltenVK keeps and later re-signals its acquire fence.
                // Always isolate the original driver's per-use native backing.
                let completion = self.private_fence(device.clone())?;
                let chain = self.wsi.swapchains.get_mut(&a[1]).unwrap();
                let (index, suboptimal) = unsafe {
                    loader.acquire_next_image(
                        chain.native.raw,
                        0,
                        semaphore
                            .as_ref()
                            .map_or(vk::Semaphore::null(), |s| vk::Semaphore::from_raw(s.raw)),
                        vk::Fence::from_raw(completion.raw),
                    )
                }?;
                if index as usize >= chain.images.len() {
                    return Err(vk::Result::ERROR_DEVICE_LOST.into());
                }
                chain.acquired[index as usize] = true;
                if let Some(fence) = fence {
                    *fence.acquisition.borrow_mut() = Some(completion.clone());
                }
                let mut retained = Vec::new();
                if let Some(s) = semaphore {
                    s.state.set(1);
                    retained.push(s);
                }
                retained.push(completion.clone());
                let previous = chain
                    .native
                    .retained
                    .borrow_mut()
                    .insert(index, retained)
                    .unwrap_or_default();
                let image = self.objects[&chain.images[index as usize]].clone();
                let mut resources = previous;
                resources.push(image);
                // The image keeps the swapchain alive, and its current retained
                // set keeps completion/semaphore objects through final cleanup.
                self.submissions.push(Submission {
                    fence: completion,
                    commands: Vec::new(),
                    _resources: resources,
                    timeline_completion: Vec::new(),
                    timeline_signals: Vec::new(),
                    commands_complete: false,
                });
                if let Err(error) = write(m, a[4], &index.to_le_bytes()) {
                    // Native acquisition happened: do not reuse an unpublished index.
                    chain.retired = true;
                    return Err(error);
                }
                if suboptimal {
                    return Err(vk::Result::SUBOPTIMAL_KHR.into());
                }
            }
            91 => {
                if a[1] != self.queue_id {
                    return invalid();
                }
                let chain = self
                    .wsi
                    .swapchains
                    .get(&a[2])
                    .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_DATE_KHR))?;
                if chain.retired
                    || a[3] >= chain.images.len() as u64
                    || !chain.acquired[a[3] as usize]
                {
                    return invalid();
                }
                if !self.display.current(&chain.native.surface.target) {
                    return Err(vk::Result::ERROR_SURFACE_LOST_KHR.into());
                }
                let ids = words64(m, a[4], bounded(a[5], 64)?)?;
                let mut dependencies = Vec::new();
                let mut semaphores = Vec::new();
                for id in ids {
                    let s = self.object(id, Kind::Semaphore)?;
                    if s.flags != 0 {
                        return invalid();
                    }
                    if s.state.get() != 1 || dependencies.iter().any(|x| Rc::ptr_eq(x, &s)) {
                        return invalid();
                    }
                    semaphores.push(vk::Semaphore::from_raw(s.raw));
                    dependencies.push(s);
                }
                let chains = [chain.native.raw];
                let indices = [a[3] as u32];
                let info = vk::PresentInfoKHR::default()
                    .wait_semaphores(&semaphores)
                    .swapchains(&chains)
                    .image_indices(&indices);
                let suboptimal = match unsafe { loader.queue_present(self.queue, &info) } {
                    Ok(suboptimal) => suboptimal,
                    Err(error) => {
                        // Consumption of native waits on a failed present is driver
                        // dependent. Retire rather than reuse ambiguous semaphore state.
                        let chain = self.wsi.swapchains.get_mut(&a[2]).unwrap();
                        chain.retired = true;
                        for semaphore in &dependencies {
                            semaphore.state.set(2);
                        }
                        chain
                            .native
                            .retained
                            .borrow_mut()
                            .entry(a[3] as u32)
                            .or_default()
                            .extend(dependencies);
                        return Err(error.into());
                    }
                };
                for s in &dependencies {
                    s.state.set(0);
                }
                chain
                    .native
                    .retained
                    .borrow_mut()
                    .entry(a[3] as u32)
                    .or_default()
                    .extend(dependencies);
                chain
                    .native
                    .surface
                    .target
                    .presented
                    .fetch_add(1, Ordering::Relaxed);
                self.wsi.swapchains.get_mut(&a[2]).unwrap().acquired[a[3] as usize] = false;
                if suboptimal {
                    return Err(vk::Result::SUBOPTIMAL_KHR.into());
                }
            }
            _ => return unsupported(),
        }
        Ok(())
    }
    fn drop_chain(&mut self, id: u64) {
        if let Some(chain) = self.wsi.swapchains.remove(&id) {
            for image in chain.images {
                self.objects.remove(&image);
            }
        }
    }
}
