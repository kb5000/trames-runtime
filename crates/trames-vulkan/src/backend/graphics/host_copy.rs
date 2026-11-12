// SPDX-License-Identifier: GPL-3.0-or-later
//! Synchronous original-image host transfers. Guest pages need not be physically
//! contiguous. A call-owned packed CPU buffer bridges those pages; no GPU staging
//! allocation, command submission, global wait, guest pointer or lease escapes.
use super::*;

fn scratch(len: u64) -> Result<Vec<u8>> {
    let len =
        usize::try_from(len).map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
    bytes.resize(len, 0);
    Ok(bytes)
}
#[derive(Clone, Copy)]
struct Packing {
    row: u64,
    rows: u64,
    slices: u64,
    pitch: u64,
    slice: u64,
}
impl Packing {
    fn new(s: ImageShape, v: &[u64]) -> Result<Self> {
        let mut x = v.to_vec();
        x[0] = 0;
        x[6] = s.layers(&x[3..7])?.layer_count as u64;
        checked_copy(&x, s, u64::MAX)?;
        let (bw, bh, _) = block_layout(ycbcr::transfer_format(s.format, x[3])?.as_raw() as u64)
            .ok_or(Failure::Vk(vk::Result::ERROR_FORMAT_NOT_SUPPORTED))?;
        let bytes = aspect_bytes(s.format, x[3])?;
        let row = x[10].div_ceil(bw) * bytes;
        let rows = x[11].div_ceil(bh);
        let slices = s.layers(&x[3..7])?.layer_count as u64 * x[12];
        let pitch = if x[1] == 0 { row } else { x[1] / bw * bytes };
        let slice = if x[2] == 0 { rows } else { x[2] / bh } * pitch;
        Ok(Self {
            row,
            rows,
            slices,
            pitch,
            slice,
        })
    }
    fn size(self) -> u64 {
        self.row * self.rows * self.slices
    }
    fn spans(self, mut f: impl FnMut(u64, usize, usize) -> Result<()>) -> Result<()> {
        if self.pitch == self.row && self.slice == self.row * self.rows {
            return f(0, 0, self.size() as usize);
        }
        for z in 0..self.slices {
            for y in 0..self.rows {
                f(
                    z * self.slice + y * self.pitch,
                    ((z * self.rows + y) * self.row) as usize,
                    self.row as usize,
                )?;
            }
        }
        Ok(())
    }
}
impl Backend {
    pub(in crate::backend) fn host_image_query(
        &self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let instance = self.instance.as_ref().unwrap();
        let query = ash::khr::get_physical_device_properties2::Instance::new(
            &instance._entry,
            &instance.native,
        );
        if op == 256 {
            if self.capabilities.compute.extensions & compute::EXT_FORMAT_FEATURE_FLAGS2 == 0 {
                return unsupported();
            }
            let mut flags = vk::FormatProperties3::default();
            let mut properties = vk::FormatProperties2::default().push_next(&mut flags);
            unsafe {
                query.get_physical_device_format_properties2(
                    self.physical,
                    vk::Format::from_raw(a[1] as i32),
                    &mut properties,
                );
            }
            return write_words(
                m,
                a[2],
                &[
                    flags.linear_tiling_features.as_raw(),
                    flags.optimal_tiling_features.as_raw(),
                    flags.buffer_features.as_raw(),
                ],
                24,
            );
        }
        if self.capabilities.compute.extensions & compute::EXT_HOST_IMAGE_COPY == 0 {
            return unsupported();
        }
        if op == 257 {
            // Query native array counts before allocating. Guest capacities never
            // size an allocation or alter the native layout list/UUID.
            let h = words64(m, a[1], 6)?;
            let mut p = vk::PhysicalDeviceHostImageCopyPropertiesEXT::default();
            let mut properties = vk::PhysicalDeviceProperties2::default().push_next(&mut p);
            unsafe {
                query.get_physical_device_properties2(self.physical, &mut properties);
            }
            let mut src = vec![vk::ImageLayout::UNDEFINED; p.copy_src_layout_count as usize];
            let mut dst = vec![vk::ImageLayout::UNDEFINED; p.copy_dst_layout_count as usize];
            p = p.copy_src_layouts(&mut src).copy_dst_layouts(&mut dst);
            let mut properties = vk::PhysicalDeviceProperties2::default().push_next(&mut p);
            unsafe {
                query.get_physical_device_properties2(self.physical, &mut properties);
            }
            let uuid = p.optimal_tiling_layout_uuid;
            let identical = p.identical_memory_type_requirements;
            let src_n = if h[1] == 0 {
                src.len()
            } else {
                src.len().min(h[0] as usize)
            };
            let dst_n = if h[3] == 0 {
                dst.len()
            } else {
                dst.len().min(h[2] as usize)
            };
            if h[1] != 0 {
                write(
                    m,
                    h[1],
                    &src[..src_n]
                        .iter()
                        .flat_map(|v| v.as_raw().to_le_bytes())
                        .collect::<Vec<_>>(),
                )?;
            }
            if h[3] != 0 {
                write(
                    m,
                    h[3],
                    &dst[..dst_n]
                        .iter()
                        .flat_map(|v| v.as_raw().to_le_bytes())
                        .collect::<Vec<_>>(),
                )?;
            }
            write(m, h[4], &uuid)?;
            write(m, h[5], &identical.to_le_bytes())?;
            return write_words(
                m,
                a[1],
                &[src_n as u64, h[1], dst_n as u64, h[3], h[4], h[5]],
                48,
            );
        }
        let formats = words32(m, a[7], bounded(a[8], 16)?)?
            .into_iter()
            .map(view_format)
            .collect::<Result<Vec<_>>>()?;
        let mut list = vk::ImageFormatListCreateInfo::default().view_formats(&formats);
        let mut stencil = vk::ImageStencilUsageCreateInfo::default()
            .stencil_usage(vk::ImageUsageFlags::from_raw(a[9] as u32));
        let mut info = vk::PhysicalDeviceImageFormatInfo2::default()
            .format(format(a[1])?)
            .ty(image_type(a[2])?)
            .tiling(vk::ImageTiling::from_raw(a[3] as i32))
            .usage(format_usage(format(a[1])?, a[4])?)
            .flags(vk::ImageCreateFlags::from_raw(a[5] as u32));
        if !formats.is_empty() {
            info = info.push_next(&mut list);
        }
        if a[9] != 0 {
            info = info.push_next(&mut stencil);
        }
        let mut perf = vk::HostImageCopyDevicePerformanceQueryEXT::default();
        let mut props = vk::ImageFormatProperties2::default().push_next(&mut perf);
        unsafe {
            query.get_physical_device_image_format_properties2(self.physical, &info, &mut props)
        }?;
        let bytes = [
            perf.optimal_device_access.to_le_bytes(),
            perf.identical_memory_layout.to_le_bytes(),
        ]
        .concat();
        write(m, a[6], &bytes)
    }
    fn host_layout(
        &self,
        image: &Object,
        sub: vk::ImageSubresource,
    ) -> (vk::SubresourceLayout, u64) {
        let d = &image.device;
        let api = &d.commands.host_copy;
        let mut size = vk::SubresourceHostMemcpySizeEXT::default();
        let mut out = vk::SubresourceLayout2EXT::default().push_next(&mut size);
        unsafe {
            api.get_image_subresource_layout2(
                vk::Image::from_raw(image.raw),
                &vk::ImageSubresource2EXT::default().image_subresource(sub),
                &mut out,
            );
        }
        (out.subresource_layout, size.size)
    }
    pub(in crate::backend) fn host_image_call(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let d = self.device(a[0])?;
        if (op != 263 && d.compute_features & compute::HOST_IMAGE_COPY == 0)
            || (op == 263 && d.compute_extensions & compute::EXT_HOST_IMAGE_COPY == 0)
        {
            return unsupported();
        }
        let api = &d.commands.host_copy;
        if op == 262 {
            let v = words64(m, a[1], bounded(a[2], 256)? * 8)?;
            let mut native = Vec::new();
            let mut owned = Vec::new();
            for x in v.chunks_exact(8) {
                let image = self.object(x[0], Kind::Image)?;
                let s = shape(&image)?;
                if image.flags & vk::ImageUsageFlags::HOST_TRANSFER_EXT.as_raw() == 0 {
                    return invalid();
                }
                native.push(
                    vk::HostImageLayoutTransitionInfoEXT::default()
                        .image(vk::Image::from_raw(image.raw))
                        .old_layout(vk::ImageLayout::from_raw(x[1] as i32))
                        .new_layout(vk::ImageLayout::from_raw(x[2] as i32))
                        .subresource_range(s.range(&x[3..8])?),
                );
                owned.push(image);
            }
            unsafe { api.transition_image_layout(&native) }?;
            return Ok(());
        }
        let image = self.object(a[1], Kind::Image)?;
        let s = shape(&image)?;
        if op == 263 {
            let sub = vk::ImageSubresource::default()
                .aspect_mask(vk::ImageAspectFlags::from_raw(a[2] as u32))
                .mip_level(a[3] as u32)
                .array_layer(a[4] as u32);
            let _ = s.range(&[a[2], a[3], 1, a[4], 1])?;
            let (v, size) = self.host_layout(&image, sub);
            write_words(
                m,
                a[5],
                &[v.offset, v.size, v.row_pitch, v.array_pitch, v.depth_pitch],
                40,
            )?;
            if a[6] != 0 {
                write(m, a[6], &size.to_le_bytes())?;
            }
            return Ok(());
        }
        if image.flags & vk::ImageUsageFlags::HOST_TRANSFER_EXT.as_raw() == 0 || a[4] & !1 != 0 {
            return invalid();
        }
        self.coherent_host_image(m, &image, true)?;
        if op == 261 {
            let dst = self.object(a[5], Kind::Image)?;
            if dst.flags & vk::ImageUsageFlags::HOST_TRANSFER_EXT.as_raw() == 0 {
                return invalid();
            }
            self.coherent_host_image(m, &dst, true)?;
            let wire = words64(m, a[7], bounded(a[8], 256)? * 17)?;
            let regions = wire
                .chunks_exact(17)
                .map(|x| {
                    checked_image_copy(x, s, shape(&dst)?).map(|v| {
                        vk::ImageCopy2::default()
                            .src_subresource(v.src_subresource)
                            .src_offset(v.src_offset)
                            .dst_subresource(v.dst_subresource)
                            .dst_offset(v.dst_offset)
                            .extent(v.extent)
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let info = vk::CopyImageToImageInfoEXT::default()
                .flags(vk::HostImageCopyFlagsEXT::from_raw(a[4] as u32))
                .src_image(vk::Image::from_raw(image.raw))
                .src_image_layout(vk::ImageLayout::from_raw(a[2] as i32))
                .dst_image(vk::Image::from_raw(dst.raw))
                .dst_image_layout(vk::ImageLayout::from_raw(a[6] as i32))
                .regions(&regions);
            unsafe { api.copy_image_to_image(&info) }?;
            self.coherent_host_image(m, &dst, false)?;
            return Ok(());
        }
        let wire = words64(m, a[5], bounded(a[6], 256)? * 13)?;
        for x in wire.chunks_exact(13) {
            let sub = checked_region(s, &x[3..7], &x[7..10], &x[10..13])?;
            let packing = if a[4] & 1 != 0 {
                let (_, size) = self.host_layout(
                    &image,
                    vk::ImageSubresource::default()
                        .aspect_mask(sub.aspect_mask)
                        .mip_level(sub.mip_level)
                        .array_layer(sub.base_array_layer),
                );
                let row = size
                    .checked_mul(sub.layer_count as u64)
                    .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
                Packing {
                    row,
                    rows: 1,
                    slices: 1,
                    pitch: row,
                    slice: row,
                }
            } else {
                Packing::new(s, x)?
            };
            let mut bytes = scratch(packing.size())?;
            let address = |offset: u64| {
                x[0].checked_add(offset)
                    .ok_or(Failure::Memory(MemoryError::InvalidRange))
            };
            packing.spans(|offset, at, len| {
                let address = address(offset)?;
                if op == 259 {
                    m.read(address, &mut bytes[at..at + len])?;
                } else {
                    output(m, address, len)?;
                }
                Ok(())
            })?;
            let extent = vk::Extent3D {
                width: x[10] as u32,
                height: x[11] as u32,
                depth: x[12] as u32,
            };
            let offset = vk::Offset3D {
                x: x[7] as i32,
                y: x[8] as i32,
                z: x[9] as i32,
            };
            if op == 259 {
                let regions = [vk::MemoryToImageCopyEXT::default()
                    .host_pointer(bytes.as_ptr().cast())
                    .image_subresource(sub)
                    .image_offset(offset)
                    .image_extent(extent)];
                let info = vk::CopyMemoryToImageInfoEXT::default()
                    .flags(vk::HostImageCopyFlagsEXT::from_raw(a[4] as u32))
                    .dst_image(vk::Image::from_raw(image.raw))
                    .dst_image_layout(vk::ImageLayout::from_raw(a[2] as i32))
                    .regions(&regions);
                unsafe { api.copy_memory_to_image(&info) }?;
            } else {
                let regions = [vk::ImageToMemoryCopyEXT::default()
                    .host_pointer(bytes.as_mut_ptr().cast())
                    .image_subresource(sub)
                    .image_offset(offset)
                    .image_extent(extent)];
                let info = vk::CopyImageToMemoryInfoEXT::default()
                    .flags(vk::HostImageCopyFlagsEXT::from_raw(a[4] as u32))
                    .src_image(vk::Image::from_raw(image.raw))
                    .src_image_layout(vk::ImageLayout::from_raw(a[2] as i32))
                    .regions(&regions);
                unsafe { api.copy_image_to_memory(&info) }?;
                packing
                    .spans(|offset, at, len| write(m, address(offset)?, &bytes[at..at + len]))?;
            }
        }
        if op == 259 {
            self.coherent_host_image(m, &image, false)?;
        }
        Ok(())
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    const OUT: u64 = 0x2000;
    fn call(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> u64 {
        let mut a = [0; 16];
        a[..args.len()].copy_from_slice(args);
        assert_eq!(
            b.invoke_graph(m, op, a).unwrap(),
            Invocation::Complete(0),
            "operation {op}"
        );
        m.read_u64(OUT).unwrap()
    }
    fn setup() -> (Backend, Memory, u64, u64) {
        let mut b = Backend::with_budget(crate::Budget::host_managed());
        let mut m = Memory::default();
        m.map(0x1000, 0x40000, Permissions::RW).unwrap();
        let instance = call(&mut b, &mut m, 1, &[OUT]);
        m.write_array(0x2100, 1u32.to_le_bytes()).unwrap();
        let physical = call(&mut b, &mut m, 3, &[instance, 0x2100, OUT]);
        (b, m, instance, physical)
    }
    fn words(m: &mut Memory, at: u64, values: &[u64]) {
        m.write(
            at,
            &values
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }
    fn image(b: &mut Backend, m: &mut Memory, device: u64) -> u64 {
        let flags = (vk::ImageUsageFlags::HOST_TRANSFER_EXT
            | vk::ImageUsageFlags::SAMPLED
            | vk::ImageUsageFlags::TRANSFER_SRC
            | vk::ImageUsageFlags::TRANSFER_DST)
            .as_raw() as u64;
        let image = call(
            b,
            m,
            60,
            &[device, 37, 8, 4, flags, OUT, 0, 0, 0, 0, 1, 1, 1, 2, 1, 0],
        );
        call(b, m, 62, &[device, image, OUT]);
        let size = m.read_u64(OUT).unwrap();
        let bits = read32(m, OUT + 16).unwrap();
        let memory = call(b, m, 14, &[device, size, bits.trailing_zeros() as u64, OUT]);
        call(b, m, 63, &[device, image, memory, 0]);
        image
    }
    #[test]
    #[ignore = "requires original native host image copy and optimal images"]
    fn hardware_host_image_copies_cross_guarded_guest_rows_and_preserve_padding() {
        let (mut b, mut m, instance, physical) = setup();
        let device = call(
            &mut b,
            &mut m,
            8,
            &[
                physical,
                0,
                OUT,
                0,
                0,
                0,
                (1 << 39) | (1 << 40) | (1 << 41),
                0,
                1 << 46,
            ],
        );
        let a = image(&mut b, &mut m, device);
        let dest = image(&mut b, &mut m, device);
        words(
            &mut m,
            0x3000,
            &[a, 0, 1, 1, 0, 1, 0, 2, dest, 0, 1, 1, 0, 1, 0, 2],
        );
        call(&mut b, &mut m, 262, &[device, 0x3000, 2]);
        for row in 0..4u64 {
            m.unmap(0x11000 + row * 0x2000, 0x1000).unwrap();
            m.unmap(0x19000 + row * 0x2000, 0x1000).unwrap();
            m.write(0x10001 + row * 0x2000, &[0x31 + row as u8; 32])
                .unwrap();
            m.write(0x18000 + row * 0x2000, &[0xa5; 96]).unwrap();
        }
        words(
            &mut m,
            0x3000,
            &[0x10001, 2048, 4, 1, 0, 1, 1, 0, 0, 0, 8, 4, 1],
        );
        call(&mut b, &mut m, 259, &[device, a, 1, 0, 0, 0x3000, 1]);
        words(
            &mut m,
            0x3000,
            &[0x18003, 2048, 4, 1, 0, 1, 1, 0, 0, 0, 8, 4, 1],
        );
        call(&mut b, &mut m, 260, &[device, a, 1, 0, 0, 0x3000, 1]);
        for row in 0..4u64 {
            let bytes = m.read_array::<96>(0x18000 + row * 0x2000).unwrap();
            assert_eq!(&bytes[..3], &[0xa5; 3]);
            assert_eq!(&bytes[3..35], &[0x31 + row as u8; 32]);
            assert!(bytes[35..].iter().all(|v| *v == 0xa5));
            assert!(m.check(0x19000 + row * 0x2000, 1, Access::Read).is_err());
        }
        // Native image-to-image, followed by a real readback, not a transport-only check.
        words(
            &mut m,
            0x3000,
            &[1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 8, 4, 1],
        );
        call(
            &mut b,
            &mut m,
            261,
            &[device, a, 1, 0, 0, dest, 1, 0x3000, 1],
        );
        words(
            &mut m,
            0x3000,
            &[0x20000, 0, 0, 1, 0, 0, 1, 0, 0, 0, 8, 4, 1],
        );
        call(&mut b, &mut m, 260, &[device, dest, 1, 0, 0, 0x3000, 1]);
        for row in 0..4u64 {
            assert_eq!(
                m.read_array::<32>(0x20000 + row * 32).unwrap(),
                [0x31 + row as u8; 32]
            );
        }
        // Opaque MEMCPY uses the actual native subresource size/layout and UUID.
        call(&mut b, &mut m, 263, &[device, a, 1, 0, 1, 0x3000, 0x3100]);
        assert!(m.read_u64(0x3100).unwrap() > 0);
        words(
            &mut m,
            0x3000,
            &[0x24000, 0, 0, 1, 0, 1, 1, 0, 0, 0, 8, 4, 1],
        );
        call(&mut b, &mut m, 260, &[device, a, 1, 0, 1, 0x3000, 1]);
        call(&mut b, &mut m, 259, &[device, dest, 1, 0, 1, 0x3000, 1]);
        words(
            &mut m,
            0x3000,
            &[0x20000, 0, 0, 1, 0, 1, 1, 0, 0, 0, 8, 4, 1],
        );
        call(&mut b, &mut m, 260, &[device, dest, 1, 0, 0, 0x3000, 1]);
        for row in 0..4u64 {
            assert_eq!(
                m.read_array::<32>(0x20000 + row * 32).unwrap(),
                [0x31 + row as u8; 32]
            );
        }
        call(&mut b, &mut m, 9, &[device]);
        call(&mut b, &mut m, 2, &[instance]);
        assert_eq!(b.live_objects.get(), 0);
        assert_eq!(b.budget.used(), 0);
    }
    #[test]
    #[ignore = "requires original native host image layout enumeration"]
    fn hardware_host_properties_bound_oversized_output_and_keep_native_identity() {
        let (mut b, mut m, instance, physical) = setup();
        words(&mut m, 0x2200, &[0, 0, 0, 0, 0x3000, 0x3010]);
        call(&mut b, &mut m, 257, &[physical, 0x2200]);
        let src = m.read_u64(0x2200).unwrap();
        let dst = m.read_u64(0x2210).unwrap();
        assert!(src > 0 && src < 64 && dst > 0 && dst < 64);
        let uuid = m.read_array::<16>(0x3000).unwrap();
        m.write(0x4000, &[0xcd; 256]).unwrap();
        m.write(0x5000, &[0xcd; 256]).unwrap();
        words(&mut m, 0x2200, &[64, 0x4000, 64, 0x5000, 0x3000, 0x3010]);
        call(&mut b, &mut m, 257, &[physical, 0x2200]);
        assert_eq!(m.read_u64(0x2200).unwrap(), src);
        assert_eq!(m.read_u64(0x2210).unwrap(), dst);
        assert_eq!(m.read_array::<16>(0x3000).unwrap(), uuid);
        assert_eq!(m.read_array::<4>(0x4000 + src * 4).unwrap(), [0xcd; 4]);
        assert_eq!(m.read_array::<4>(0x5000 + dst * 4).unwrap(), [0xcd; 4]);
        call(&mut b, &mut m, 256, &[physical, 37, 0x3000]);
        assert!(
            m.read_u64(0x3008).unwrap() & vk::FormatFeatureFlags2::HOST_IMAGE_TRANSFER_EXT.as_raw()
                != 0
        );
        // Mesa adds the sample-compatible depth flag even without MSAA. It
        // must reach the native query/create path rather than the old whitelist.
        let device = call(&mut b, &mut m, 8, &[physical, 0, OUT]);
        let image = call(
            &mut b,
            &mut m,
            60,
            &[
                device, 126, 8, 8, 0x27, OUT, 0, 0, 0, 0x1000, 1, 1, 1, 2, 1, 0,
            ],
        );
        call(&mut b, &mut m, 61, &[device, image]);
        call(&mut b, &mut m, 2, &[instance]);
    }
    #[test]
    #[ignore = "requires original native fence completion and mapped memory"]
    fn hardware_async_poll_reports_readback_delta_without_recounting_mapping() {
        let (mut b, mut m, _, physical) = setup();
        let device = call(&mut b, &mut m, 8, &[physical, 0, OUT]);
        let length = trames_memory::PAGE_SIZE;
        let guest = 0x80000;
        m.map(guest, length, Permissions::RW).unwrap();
        let buffer = call(&mut b, &mut m, 11, &[device, length, 3, OUT]);
        call(&mut b, &mut m, 13, &[device, buffer, OUT]);
        let size = m.read_u64(OUT).unwrap();
        let bits = read32(&m, OUT + 16).unwrap();
        let props = unsafe {
            b.instance
                .as_ref()
                .unwrap()
                .native
                .get_physical_device_memory_properties(b.physical)
        };
        let ty = (0..props.memory_type_count)
            .find(|i| {
                bits & (1 << i) != 0
                    && props.memory_types[*i as usize].property_flags.contains(
                        vk::MemoryPropertyFlags::HOST_VISIBLE
                            | vk::MemoryPropertyFlags::HOST_COHERENT,
                    )
            })
            .unwrap();
        let memory = call(&mut b, &mut m, 14, &[device, size, ty as u64, OUT]);
        call(&mut b, &mut m, 16, &[device, buffer, memory, 0]);
        // An original client without the optional shared-map bridge keeps the
        // correct shadow path; its async readback must still appear in metrics.
        call(&mut b, &mut m, 17, &[device, memory, 0, length, guest]);
        assert!(b.mappings[&memory].coherent.is_some());
        let expected = m.read_u64(guest).unwrap() ^ u64::MAX;
        unsafe { (b.objects[&memory].mapped.get() as *mut u64).write(expected) };
        b.coherent_pending
            .extend(&coherent::Scope::resources(&[b.objects[&buffer].clone()]));
        let fence = call(&mut b, &mut m, 48, &[device, 0, OUT]);
        m.write_array(0x3000, fence.to_le_bytes()).unwrap();
        let mut args = [0; 16];
        args[..6].copy_from_slice(&[device, 0x3000, 1, 1, u64::MAX, 0]);
        let Invocation::Pending(job) = b.invoke_graph(&mut m, 201, args).unwrap() else {
            panic!("unsignaled original fence must return a pending wait")
        };
        let native = &b.objects[&fence].device.native;
        let raw = vk::Fence::from_raw(b.objects[&fence].raw);
        unsafe {
            native.queue_submit(b.queue, &[], raw).unwrap();
            native.wait_for_fences(&[raw], true, u64::MAX).unwrap();
        }
        let context = crate::Context::new(b);
        let (result, transfers) = context.try_lock().unwrap().poll_with_transfers(&mut m, job);
        assert_eq!(result.unwrap(), Some(0));
        assert_eq!(m.read_u64(guest).unwrap(), expected);
        assert_eq!(transfers.coherent_download_scanned_bytes, length);
        assert_eq!(transfers.download_bytes, 8);
        assert_eq!(transfers.upload_bytes, 0);
        assert_eq!(transfers.shared_maps, 0);
    }
    #[test]
    #[ignore = "requires original aligned native Vulkan host mapping"]
    fn hardware_original_native_mapping_outlives_logical_handles_without_importing_memory() {
        for length in [1u64 << 20, (1u64 << 20) + trames_memory::PAGE_SIZE] {
            let (mut b, mut m, instance, physical) = setup();
            let device = call(&mut b, &mut m, 8, &[physical, 0, OUT]);
            let guest = 0x80000;
            m.map(guest, length, Permissions::RW).unwrap();
            let buffer = call(&mut b, &mut m, 11, &[device, length, 3, OUT]);
            call(&mut b, &mut m, 13, &[device, buffer, OUT]);
            let size = m.read_u64(OUT).unwrap();
            let bits = read32(&m, OUT + 16).unwrap();
            let props = unsafe {
                b.instance
                    .as_ref()
                    .unwrap()
                    .native
                    .get_physical_device_memory_properties(b.physical)
            };
            let ty = (0..props.memory_type_count)
                .find(|i| {
                    bits & (1 << i) != 0
                        && props.memory_types[*i as usize].property_flags.contains(
                            vk::MemoryPropertyFlags::HOST_VISIBLE
                                | vk::MemoryPropertyFlags::HOST_COHERENT,
                        )
                })
                .unwrap();
            let requested = size.max(length);
            let memory = call(&mut b, &mut m, 14, &[device, requested, ty as u64, OUT]);
            let charged = requested.next_multiple_of(trames_memory::host_mapping_granule() as u64);
            assert_eq!(b.objects[&memory].size, requested);
            assert_eq!(b.objects[&memory].allocation_size.get(), charged);
            assert!(
                b.objects[&memory].host_allocation.borrow().is_none(),
                "generic allocations retain their original native backing"
            );
            let too_large = call(
                &mut b,
                &mut m,
                11,
                &[device, requested + trames_memory::PAGE_SIZE, 3, OUT],
            );
            let mut args = [0; 16];
            args[..4].copy_from_slice(&[device, too_large, memory, 0]);
            assert!(
                matches!(b.invoke_graph(&mut m, 16, args).unwrap(), Invocation::Complete(value) if (value as i64) < 0)
            );
            call(&mut b, &mut m, 12, &[device, too_large]);
            // Native generic allocations keep image/buffer aliasing; they are not
            // converted to buffer-only external imports or dedicated allocations.
            let native = &b.objects[&memory].device.native;
            let image_info = vk::ImageCreateInfo::default()
                .flags(vk::ImageCreateFlags::ALIAS)
                .image_type(vk::ImageType::TYPE_2D)
                .format(vk::Format::R8G8B8A8_UNORM)
                .extent(vk::Extent3D {
                    width: 4,
                    height: 4,
                    depth: 1,
                })
                .mip_levels(1)
                .array_layers(1)
                .samples(vk::SampleCountFlags::TYPE_1)
                .tiling(vk::ImageTiling::LINEAR)
                .usage(vk::ImageUsageFlags::TRANSFER_DST);
            let image = unsafe { native.create_image(&image_info, None).unwrap() };
            let image_requirements = unsafe { native.get_image_memory_requirements(image) };
            assert_ne!(image_requirements.memory_type_bits & (1 << ty), 0);
            assert!(image_requirements.size <= requested);
            unsafe {
                native
                    .bind_image_memory(image, vk::DeviceMemory::from_raw(b.objects[&memory].raw), 0)
                    .unwrap()
            };
            call(&mut b, &mut m, 16, &[device, buffer, memory, 0]);
            let mut args = [0; 16];
            args[..6].copy_from_slice(&[
                device,
                memory,
                0,
                requested + trames_memory::PAGE_SIZE,
                guest,
                shared_memory::MAP_SHARED,
            ]);
            assert!(
                matches!(b.invoke_graph(&mut m, 17, args).unwrap(), Invocation::Complete(value) if (value as i64) < 0)
            );
            call(
                &mut b,
                &mut m,
                17,
                &[device, memory, 0, length, guest, shared_memory::MAP_SHARED],
            );
            assert!(b.mappings[&memory].direct);
            {
                let object = &b.objects[&memory];
                let owner = object.host_allocation.borrow();
                let owner = owner.as_ref().unwrap();
                assert!(owner.owns_native());
                // SAFETY: this test synchronously owns the original mapped native bytes.
                unsafe {
                    owner.pointer().cast::<u64>().write(0x0123456789abcdef);
                }
            }
            assert_eq!(m.read_u64(guest).unwrap(), 0x0123456789abcdef);
            call(&mut b, &mut m, 18, &[device, memory]);
            let partial = 0x300000;
            let page = trames_memory::PAGE_SIZE;
            m.map(partial, 3 * page, Permissions::RW).unwrap();
            call(
                &mut b,
                &mut m,
                17,
                &[
                    device,
                    memory,
                    page,
                    3 * page,
                    partial,
                    shared_memory::MAP_SHARED,
                ],
            );
            assert!(b.mappings[&memory].direct);
            m.write_array(partial, 0xfedcba9876543210u64.to_le_bytes())
                .unwrap();
            assert_eq!(m.read_u64(guest + page).unwrap(), 0xfedcba9876543210);
            call(&mut b, &mut m, 18, &[device, memory]);
            let tail = 0x400000;
            m.map(tail, page, Permissions::RW).unwrap();
            call(
                &mut b,
                &mut m,
                17,
                &[
                    device,
                    memory,
                    length - page,
                    page,
                    tail,
                    shared_memory::MAP_SHARED,
                ],
            );
            assert!(b.mappings[&memory].direct);
            m.write_array(tail, 0x1122334455667788u64.to_le_bytes())
                .unwrap();
            assert_eq!(
                m.read_u64(guest + length - page).unwrap(),
                0x1122334455667788
            );
            call(&mut b, &mut m, 18, &[device, memory]);
            call(
                &mut b,
                &mut m,
                17,
                &[device, memory, 0, length, guest, shared_memory::MAP_SHARED],
            );
            assert!(b.mappings[&memory].direct);
            assert_eq!(m.read_u64(guest).unwrap(), 0x0123456789abcdef);
            call(&mut b, &mut m, 18, &[device, memory]);
            unsafe { b.objects[&memory].device.native.destroy_image(image, None) };
            call(&mut b, &mut m, 12, &[device, buffer]);
            call(&mut b, &mut m, 15, &[device, memory]);
            call(&mut b, &mut m, 9, &[device]);
            call(&mut b, &mut m, 2, &[instance]);
            assert_eq!(b.live_objects.get(), 0);
            assert_eq!(b.budget.used(), charged);
            assert_eq!(m.read_u64(guest).unwrap(), 0x0123456789abcdef);
            m.unmap(guest, length).unwrap();
            assert_eq!(
                b.budget.used(),
                charged,
                "partial guest views retain the real owner"
            );
            m.unmap(partial, 3 * page).unwrap();
            m.unmap(tail, page).unwrap();
            assert_eq!(b.budget.used(), 0);
        }
    }
}
