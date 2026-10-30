// SPDX-License-Identifier: GPL-3.0-or-later
//! Selected core 1.0 graphics for allocated and borrowed swapchain images. No guest Vulkan structure/pointer is
//! handed to the driver; all arrays are decoded to scoped native records.
use super::*;
mod render_pass;
mod render_graph;
mod commands;
mod ycbcr;

#[derive(Clone, Copy)]
pub(super) struct ImageShape {
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) format: vk::Format,
    pub(super) ty: vk::ImageType,
    pub(super) depth: u32,
    pub(super) mips: u32,
    pub(super) layers: u32,
    pub(super) samples: vk::SampleCountFlags,
    pub(super) tiling: vk::ImageTiling,
}
impl ImageShape {
    pub(super) fn d2(width: u32, height: u32, format: vk::Format) -> Self {
        Self {
            width,
            height,
            format,
            ty: vk::ImageType::TYPE_2D,
            depth: 1,
            mips: 1,
            layers: 1,
            samples: vk::SampleCountFlags::TYPE_1,
            tiling: vk::ImageTiling::OPTIMAL,
        }
    }
    fn extent(self, mip: u64) -> Result<[u32; 3]> {
        if mip >= self.mips as u64 {
            return invalid();
        }
        Ok([self.width, self.height, self.depth].map(|n| (n >> mip).max(1)))
    }
    fn aspect(self) -> vk::ImageAspectFlags {
        format_aspects(self.format)
    }
    fn range(self, wire: &[u64]) -> Result<vk::ImageSubresourceRange> {
        let plane=ycbcr::plane(self.format.as_raw() as u64,wire[0]).is_some();
        if wire[0] == 0 || !plane && wire[0] & !(self.aspect().as_raw() as u64) != 0 {
            return invalid();
        }
        let count = |base: u64, count: u64, total: u32| -> Result<u32> {
            if base >= total as u64 {
                return invalid();
            }
            let count = if count == u32::MAX as u64 {
                total as u64 - base
            } else {
                count
            };
            if count == 0 || count > total as u64 - base {
                return invalid();
            }
            Ok(count as u32)
        };
        Ok(vk::ImageSubresourceRange::default()
            .aspect_mask(vk::ImageAspectFlags::from_raw(wire[0] as u32))
            .base_mip_level(wire[1] as u32)
            .level_count(count(wire[1], wire[2], self.mips)?)
            .base_array_layer(wire[3] as u32)
            .layer_count(count(wire[3], wire[4], self.layers)?))
    }
    fn whole(self) -> vk::ImageSubresourceRange {
        vk::ImageSubresourceRange::default()
            .aspect_mask(self.aspect())
            .level_count(self.mips)
            .layer_count(self.layers)
    }
    fn layers(self, wire: &[u64]) -> Result<vk::ImageSubresourceLayers> {
        let r = self.range(&[wire[0], wire[1], 1, wire[2], wire[3]])?;
        Ok(vk::ImageSubresourceLayers::default()
            .aspect_mask(r.aspect_mask)
            .mip_level(r.base_mip_level)
            .base_array_layer(r.base_array_layer)
            .layer_count(r.layer_count))
    }
    fn attachment(self) -> bool {
        self.ty == vk::ImageType::TYPE_2D && self.mips == 1
    }
}
#[derive(Clone, Debug)]
pub(super) struct SubpassInfo {
    colors: [vk::Format; MAX_COLORS],
    color_count: usize,
    depth: Option<vk::Format>,
    samples: vk::SampleCountFlags,
    view_mask: u32,
    inputs: Vec<(vk::Format,vk::SampleCountFlags)>,
    resolves: Vec<(vk::Format,vk::SampleCountFlags)>,
    depth_resolve: Option<(vk::Format,u32,u32)>,
}
impl SubpassInfo {
    fn new(color_count:usize)->Self {Self {colors:[vk::Format::UNDEFINED;MAX_COLORS],color_count,depth:None,samples:vk::SampleCountFlags::empty(),view_mask:0,inputs:Vec::new(),resolves:Vec::new(),depth_resolve:None}}
}
#[derive(Clone, Debug)]
pub(super) struct PassInfo {
    formats: Vec<vk::Format>,
    sample_counts: Vec<vk::SampleCountFlags>,
    usages: Vec<vk::ImageUsageFlags>,
    attachments: usize,
    clear_count: usize,
    view_mask: u32,
    subpasses: Vec<SubpassInfo>,
}
impl std::ops::Deref for PassInfo {type Target=SubpassInfo;fn deref(&self)->&SubpassInfo{&self.subpasses[0]}}
impl std::ops::DerefMut for PassInfo {fn deref_mut(&mut self)->&mut SubpassInfo{&mut self.subpasses[0]}}
impl PassInfo {
    fn new(color_count:usize)->Self {Self {formats:vec![vk::Format::UNDEFINED;MAX_ATTACHMENTS],sample_counts:vec![vk::SampleCountFlags::empty();MAX_ATTACHMENTS],usages:vec![vk::ImageUsageFlags::empty();MAX_ATTACHMENTS],attachments:0,clear_count:0,view_mask:0,subpasses:vec![SubpassInfo::new(color_count)]}}
    fn attachment_count(&self)->usize{self.attachments}
    fn attachment_format(&self,index:usize)->vk::Format{self.formats.get(index).copied().unwrap_or(vk::Format::UNDEFINED)}
    fn attachment_usage(&self,index:usize)->vk::ImageUsageFlags{self.usages[index]}
}
pub(super) struct AttachmentSpec {
    flags: vk::ImageCreateFlags,
    usage: vk::ImageUsageFlags,
    width: u32,
    height: u32,
    formats: Vec<vk::Format>,
    layers: u32,
}
#[derive(Default)]
pub(super) struct Recording {
    pub pass: Option<Rc<Object>>,
    render_area: Option<vk::Rect2D>,
    layers: u32,
    pub subpass: usize,
    pub pipeline: Option<Rc<Object>>,
    pass2: bool,
    pub compute_pipeline: Option<Rc<Object>>,
    pub vertices: BTreeMap<u32, (Rc<Object>, u64)>,
    index: Option<(Rc<Object>, u64, u32)>,
    pub viewport: bool,
    pub scissor: bool,
    pub feedback_active: bool,
    pub feedback_buffers: BTreeMap<u32, (Rc<Object>, u64, u64)>,
    pub queries: BTreeMap<(i32, u32), (Rc<Object>, u32)>,
}
#[derive(Clone)]
pub(super) struct VertexBinding {
    pub binding: u32,
    stride: u32,
    instance: bool,
    divisor: u32,
    pub extent: u32,
}
// Core uncompressed color formats. Driver queries still decide which of these
// support sampling, rendering, storage, blending or vertex input on this host.
pub(super) fn vertex_size(raw: u64) -> Option<u32> {
    if matches!(raw, 124..=130) {
        return None;
    }
    texel_size(raw)
}
fn texel_size(raw: u64) -> Option<u32> {
    match raw {
        1 | 9..=15 | 127 => Some(1),
        2..=8 | 16..=22 | 70..=76 | 124 => Some(2),
        23..=36 | 128 => Some(3),
        37..=69 | 77..=83 | 98..=100 | 122..=123 | 125..=126 | 129 => Some(4),
        84..=90 => Some(6),
        91..=97 | 101..=103 | 130 => Some(8),
        104..=106 => Some(12),
        107..=109 => Some(16),
        _ => None,
    }
}
fn compressed_block(raw: u64) -> Option<(u64, u64, u64)> {
    match raw {
        131..=134 | 139..=140 | 147..=150 | 153..=154 => Some((4, 4, 8)),
        135..=138 | 141..=146 | 151..=152 | 155..=156 => Some((4, 4, 16)),
        157..=184 => {
            const ASTC: [(u64, u64); 14] = [(4,4),(5,4),(5,5),(6,5),(6,6),(8,5),(8,6),(8,8),(10,5),(10,6),(10,8),(10,10),(12,10),(12,12)];
            let (width, height) = ASTC[((raw - 157) / 2) as usize];
            Some((width, height, 16))
        }
        _ => None,
    }
}
fn block_layout(raw: u64) -> Option<(u64, u64, u64)> {
    compressed_block(raw).or_else(|| ycbcr::packed(raw)).or_else(|| texel_size(raw).map(|bytes| (1, 1, bytes as u64)))
}
pub(super) const DIMENSION: u32 = 4096;
pub(super) const LAYERS: u32 = 2048;
pub(super) const MAX_COLORS: usize = 8;
const MAX_ATTACHMENTS: usize = MAX_COLORS * 2 + 1;
fn format(raw: u64) -> Result<vk::Format> {
    if block_layout(raw).is_some() || ycbcr::multiplane(raw) {
        Ok(vk::Format::from_raw(raw as i32))
    } else {
        Err(vk::Result::ERROR_FORMAT_NOT_SUPPORTED.into())
    }
}
// Format-list entries are metadata, not a claim that every listed format is
// creatable in this profile. Retain valid core enum entries for native image
// compatibility checks; actual images/views still pass the selected filter.
fn view_format(raw: u32) -> Result<vk::Format> {
    if !(1..=184).contains(&raw) && !(1000156000..=1000156033).contains(&raw) {
        return Err(vk::Result::ERROR_FORMAT_NOT_SUPPORTED.into());
    }
    Ok(vk::Format::from_raw(raw as i32))
}
fn usage(raw: u64) -> Result<vk::ImageUsageFlags> {
    let allowed = vk::ImageUsageFlags::COLOR_ATTACHMENT
        | vk::ImageUsageFlags::TRANSFER_SRC
        | vk::ImageUsageFlags::TRANSFER_DST
        | vk::ImageUsageFlags::SAMPLED
        | vk::ImageUsageFlags::STORAGE
        | vk::ImageUsageFlags::TRANSIENT_ATTACHMENT
        | vk::ImageUsageFlags::INPUT_ATTACHMENT
        | vk::ImageUsageFlags::DEPTH_STENCIL_ATTACHMENT;
    if raw == 0 || raw & !(allowed.as_raw() as u64) != 0 {
        return unsupported();
    }
    Ok(vk::ImageUsageFlags::from_raw(raw as u32))
}
fn layout(raw: u64, initial: bool) -> Result<vk::ImageLayout> {
    match raw {
        0 if initial => Ok(vk::ImageLayout::UNDEFINED),
        8 if initial => Ok(vk::ImageLayout::PREINITIALIZED),
        // Original Mesa's legacy render passes retain the EXT enum even when
        // its image barriers use the core GENERAL fallback. Keep all native
        // barriers/descriptors/references consistent; do not expose the EXT.
        1 | 1000339000 => Ok(vk::ImageLayout::GENERAL),
        2 => Ok(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL),
        3 => Ok(vk::ImageLayout::DEPTH_STENCIL_ATTACHMENT_OPTIMAL),
        4 => Ok(vk::ImageLayout::DEPTH_STENCIL_READ_ONLY_OPTIMAL),
        5 => Ok(vk::ImageLayout::SHADER_READ_ONLY_OPTIMAL),
        6 => Ok(vk::ImageLayout::TRANSFER_SRC_OPTIMAL),
        7 => Ok(vk::ImageLayout::TRANSFER_DST_OPTIMAL),
        1000241000..=1000241003 => Ok(vk::ImageLayout::from_raw(raw as i32)),
        1000117000 | 1000117001 => Ok(vk::ImageLayout::from_raw(raw as i32)),
        1000001002 => Ok(vk::ImageLayout::PRESENT_SRC_KHR),
        _ => unsupported(),
    }
}
fn attachment_reference_layout(raw: u64, depth: bool) -> Result<vk::ImageLayout> {
    let value = layout(raw, false)?;
    if value == vk::ImageLayout::GENERAL
        || !depth && value == vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL
        || depth
            && matches!(
                value,
                vk::ImageLayout::DEPTH_STENCIL_ATTACHMENT_OPTIMAL
                    | vk::ImageLayout::DEPTH_STENCIL_READ_ONLY_OPTIMAL
                    | vk::ImageLayout::DEPTH_ATTACHMENT_STENCIL_READ_ONLY_OPTIMAL
                    | vk::ImageLayout::DEPTH_READ_ONLY_STENCIL_ATTACHMENT_OPTIMAL
                    | vk::ImageLayout::DEPTH_ATTACHMENT_OPTIMAL | vk::ImageLayout::DEPTH_READ_ONLY_OPTIMAL
                    | vk::ImageLayout::STENCIL_ATTACHMENT_OPTIMAL | vk::ImageLayout::STENCIL_READ_ONLY_OPTIMAL
            )
    {
        Ok(value)
    } else {
        unsupported()
    }
}
fn format_aspects(format: vk::Format) -> vk::ImageAspectFlags {
    match format.as_raw() {
        124..=126 => vk::ImageAspectFlags::DEPTH,
        127 => vk::ImageAspectFlags::STENCIL,
        128..=130 => vk::ImageAspectFlags::DEPTH | vk::ImageAspectFlags::STENCIL,
        _ => vk::ImageAspectFlags::COLOR,
    }
}
fn aspect_usage(image:&Object,aspect:u32)->u32 {
    if aspect&vk::ImageAspectFlags::STENCIL.as_raw()==0{return image.flags;}
    let stencil=image.stencil_usage.get();if stencil==0{return image.flags;}
    if aspect&vk::ImageAspectFlags::DEPTH.as_raw()==0{stencil}else{image.flags&stencil}
}
fn is_depth_stencil(format: vk::Format) -> bool {
    // Includes stencil-only formats throughout the non-color resource path.
    format_aspects(format) != vk::ImageAspectFlags::COLOR
}
fn aspect_bytes(format: vk::Format, aspect: u64) -> Result<u64> {
    let format=ycbcr::transfer_format(format,aspect)?;
    let flags = if aspect&0x70!=0 {aspect}else{format_aspects(format).as_raw() as u64};
    if aspect.count_ones() != 1 || aspect & !flags != 0 {
        return invalid();
    }
    Ok(match aspect {
        4 => 1,
        2 => match format.as_raw() {
            124 | 128 => 2,
            _ => 4,
        },
        _ => block_layout(format.as_raw() as u64)
            .ok_or(Failure::Vk(vk::Result::ERROR_FORMAT_NOT_SUPPORTED))?.2,
    })
}
fn format_usage(format: vk::Format, raw: u64) -> Result<vk::ImageUsageFlags> {
    let flags = usage(raw)?;
    if is_depth_stencil(format) && flags.contains(vk::ImageUsageFlags::COLOR_ATTACHMENT)
        || !is_depth_stencil(format)
            && flags.contains(vk::ImageUsageFlags::DEPTH_STENCIL_ATTACHMENT)
    {
        return Err(vk::Result::ERROR_FORMAT_NOT_SUPPORTED.into());
    }
    Ok(flags)
}
pub(super) fn compatible_pass(a:&Object,b:&Object)->bool {
    a.pass.get().zip(b.pass.get()).is_some_and(|(a,b)|a.subpasses.len()==b.subpasses.len() && a.subpasses.iter().zip(&b.subpasses).all(|(x,y)|
        x.color_count==y.color_count && x.colors==y.colors && x.depth==y.depth && x.samples==y.samples && x.view_mask==y.view_mask && x.inputs==y.inputs
        && (a.subpasses.len()==1 || x.resolves==y.resolves && x.depth_resolve==y.depth_resolve)))
}

fn shape(object: &Object) -> Result<ImageShape> {
    object
        .image
        .get()
        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))
}
impl Backend {
    pub(super) fn indirect_call(&mut self, op: u64, a: [u64; 16]) -> Result<()> {
        let command = self.object(a[1], Kind::CommandBuffer)?;
        let buffer = self.object(a[2], Kind::Buffer)?;
        let device = &command.device;
        if command.state.get() != 1 || buffer.deps.borrow().is_empty()
            || buffer.flags & vk::BufferUsageFlags::INDIRECT_BUFFER.as_raw() == 0
        { return invalid(); }
        let dispatch = op == 205;
        let indexed = op == 204 || op==236;
        let counted=op==235||op==236;
        if counted && device.compute_features&compute::DRAW_INDIRECT_COUNT==0{return unsupported();}
        let count = if dispatch { 1 } else { a[4] };
        if !dispatch && (count > device.max_indirect_draw_count as u64
            || count > 1 && device.features.multi_draw_indirect == 0)
        { return unsupported(); }
        let size = if dispatch { 12 } else if indexed { 20 } else { 16 };
        indirect_span(buffer.size, a[3], count, a[5], size)?;
        let recording = command.recording.borrow();
        if dispatch {
            if recording.pass.is_some() || recording.compute_pipeline.is_none() { return invalid(); }
        } else {
            let pass = recording.pass.as_ref().ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
            let pipeline = recording.pipeline.as_ref().ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
            if pipeline.flags != vk::PipelineBindPoint::GRAPHICS.as_raw() as u32
                || pipeline.size as usize!=recording.subpass
                || !compatible_pass(&pipeline.deps.borrow()[1], pass)
                || !recording.viewport && pipeline.static_states.get() & 1 == 0
                || !recording.scissor && pipeline.static_states.get() & 2 == 0
                || indexed && recording.index.is_none()
                || pipeline.vertex_inputs.borrow().iter().any(|v|
                    v.extent != 0 && !recording.vertices.contains_key(&v.binding))
            { return invalid(); }
        }
        // GPU-written arguments stay on the GPU. No mapped-memory readback,
        // count expansion, descriptor rescan or extra publication barrier.
        let raw = vk::CommandBuffer::from_raw(command.raw);
        let source = vk::Buffer::from_raw(buffer.raw);
        unsafe {
            if counted {
                let counts=self.object(a[6],Kind::Buffer)?;
                if counts.flags&vk::BufferUsageFlags::INDIRECT_BUFFER.as_raw()==0 || counts.deps.borrow().is_empty() || !a[7].is_multiple_of(4) || a[7].checked_add(4).is_none_or(|end|end>counts.size){return invalid();}
                if indexed{device.native.cmd_draw_indexed_indirect_count(raw,source,a[3],vk::Buffer::from_raw(counts.raw),a[7],count as u32,a[5] as u32);}
                else{device.native.cmd_draw_indirect_count(raw,source,a[3],vk::Buffer::from_raw(counts.raw),a[7],count as u32,a[5] as u32);}command.retain(counts);
            }
            else if dispatch { device.native.cmd_dispatch_indirect(raw, source, a[3]); }
            else if indexed { device.native.cmd_draw_indexed_indirect(raw, source, a[3], count as u32, a[5] as u32); }
            else { device.native.cmd_draw_indirect(raw, source, a[3], count as u32, a[5] as u32); }
        }
        command.retain(buffer);
        Ok(())
    }
    pub(super) fn native_layout(&self, raw: u64, initial: bool) -> Result<vk::ImageLayout> {
        let value = layout(raw, initial)?;
        if (1000241000..=1000241003).contains(&value.as_raw()) && self.device.as_ref().is_none_or(|d|d.compute_features&compute::SEPARATE_DEPTH_STENCIL_LAYOUTS==0){return unsupported();}
        Ok(
            if self.virtual_wsi && value == vk::ImageLayout::PRESENT_SRC_KHR {
                vk::ImageLayout::GENERAL
            } else {
                value
            },
        )
    }
    // New native resources are owned before the final fallible guest write.
    // A backing I/O failure after preflight must not leak an unpublished object.
    pub(super) fn publish(&mut self, m: &mut impl CpuMemory, output: u64, id: u64) -> Result<()> {
        if let Err(error) = write(m, output, &id.to_le_bytes()) {
            self.objects.remove(&id);
            return Err(error);
        }
        Ok(())
    }
    fn native_image_limits(
        &self,
        f: vk::Format,
        ty: vk::ImageType,
        usage: vk::ImageUsageFlags,
        flags: vk::ImageCreateFlags,
        formats: &[vk::Format],
        tiling: vk::ImageTiling,
        stencil_usage: u32,
    ) -> Result<vk::ImageFormatProperties> {
        let instance = &self.instance.as_ref().unwrap().native;
        Ok(if formats.is_empty() && stencil_usage==0 {
            unsafe {
                instance.get_physical_device_image_format_properties(
                    self.physical,
                    f,
                    ty,
                    tiling,
                    usage,
                    flags,
                )
            }?
        } else {
            if !formats.is_empty() && self.capabilities.bits & zink::FORMAT_LIST == 0 {
                return unsupported();
            }
            let mut list = vk::ImageFormatListCreateInfo::default().view_formats(formats);
            let mut stencil=vk::ImageStencilUsageCreateInfo::default().stencil_usage(vk::ImageUsageFlags::from_raw(stencil_usage));
            let mut info = vk::PhysicalDeviceImageFormatInfo2::default()
                .format(f)
                .ty(ty)
                .tiling(tiling)
                .usage(usage)
                .flags(flags);
            if !formats.is_empty(){info=info.push_next(&mut list);}
            if stencil_usage!=0 {info=info.push_next(&mut stencil);}
            let mut properties = vk::ImageFormatProperties2::default();
            let owner = self.instance.as_ref().unwrap();
            let api =
                ash::khr::get_physical_device_properties2::Instance::new(&owner._entry, instance);
            unsafe {
                api.get_physical_device_image_format_properties2(
                    self.physical,
                    &info,
                    &mut properties,
                )
            }?;
            properties.image_format_properties
        })
    }
    pub(super) fn format_query(&self, m: &mut impl CpuMemory, op: u64, a: [u64; 16]) -> Result<()> {
        let instance = &self.instance.as_ref().unwrap().native;
        if op == 58 {
            let mut bytes = vec![0u8; 12];
            if let Ok(f) = format(a[1]) {
                let p = unsafe { instance.get_physical_device_format_properties(self.physical, f) };
                let flags = p.optimal_tiling_features
                    & (vk::FormatFeatureFlags::COLOR_ATTACHMENT
                        | vk::FormatFeatureFlags::COLOR_ATTACHMENT_BLEND
                        | vk::FormatFeatureFlags::DEPTH_STENCIL_ATTACHMENT
                        | vk::FormatFeatureFlags::TRANSFER_SRC
                        | vk::FormatFeatureFlags::TRANSFER_DST
                        | vk::FormatFeatureFlags::SAMPLED_IMAGE
                        | vk::FormatFeatureFlags::STORAGE_IMAGE
                        | vk::FormatFeatureFlags::SAMPLED_IMAGE_FILTER_LINEAR | vk::FormatFeatureFlags::SAMPLED_IMAGE_FILTER_MINMAX | vk::FormatFeatureFlags::STORAGE_IMAGE_ATOMIC | vk::FormatFeatureFlags::MIDPOINT_CHROMA_SAMPLES | vk::FormatFeatureFlags::COSITED_CHROMA_SAMPLES | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_LINEAR_FILTER | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_SEPARATE_RECONSTRUCTION_FILTER | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_CHROMA_RECONSTRUCTION_EXPLICIT | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_CHROMA_RECONSTRUCTION_EXPLICIT_FORCEABLE
                        | vk::FormatFeatureFlags::BLIT_SRC
                        | vk::FormatFeatureFlags::BLIT_DST);
                bytes[4..8].copy_from_slice(&flags.as_raw().to_le_bytes());
                let linear=p.linear_tiling_features & (vk::FormatFeatureFlags::COLOR_ATTACHMENT|vk::FormatFeatureFlags::COLOR_ATTACHMENT_BLEND|vk::FormatFeatureFlags::DEPTH_STENCIL_ATTACHMENT|vk::FormatFeatureFlags::TRANSFER_SRC|vk::FormatFeatureFlags::TRANSFER_DST|vk::FormatFeatureFlags::SAMPLED_IMAGE|vk::FormatFeatureFlags::STORAGE_IMAGE|vk::FormatFeatureFlags::SAMPLED_IMAGE_FILTER_LINEAR | vk::FormatFeatureFlags::SAMPLED_IMAGE_FILTER_MINMAX | vk::FormatFeatureFlags::STORAGE_IMAGE_ATOMIC | vk::FormatFeatureFlags::MIDPOINT_CHROMA_SAMPLES | vk::FormatFeatureFlags::COSITED_CHROMA_SAMPLES | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_LINEAR_FILTER | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_SEPARATE_RECONSTRUCTION_FILTER | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_CHROMA_RECONSTRUCTION_EXPLICIT | vk::FormatFeatureFlags::SAMPLED_IMAGE_YCBCR_CONVERSION_CHROMA_RECONSTRUCTION_EXPLICIT_FORCEABLE|vk::FormatFeatureFlags::BLIT_SRC|vk::FormatFeatureFlags::BLIT_DST);
                bytes[..4].copy_from_slice(&linear.as_raw().to_le_bytes());
            }
            if vertex_size(a[1]).is_some() {
                let p = unsafe {
                    instance.get_physical_device_format_properties(
                        self.physical,
                        vk::Format::from_raw(a[1] as i32),
                    )
                };
                bytes[8..12].copy_from_slice(
                    &(p.buffer_features
                        & (vk::FormatFeatureFlags::VERTEX_BUFFER
                            | vk::FormatFeatureFlags::UNIFORM_TEXEL_BUFFER
                            | vk::FormatFeatureFlags::STORAGE_TEXEL_BUFFER | vk::FormatFeatureFlags::STORAGE_TEXEL_BUFFER_ATOMIC))
                        .as_raw()
                        .to_le_bytes(),
                );
            }
            return write(m, a[2], &bytes);
        }
        output(m, a[6], 32)?;
        let ty = image_type(a[2])?;
        if a[3] > vk::ImageTiling::LINEAR.as_raw() as u64
            || a[5] & !0x138 != 0
            || a[5] & 16 != 0 && ty != vk::ImageType::TYPE_2D
            || a[5] & 32 != 0
                && (ty != vk::ImageType::TYPE_3D
                    || self
                        .capabilities
                        .portability
                        .is_some_and(|p| p.image_view2_d_on3_d_image == 0))
        {
            return Err(vk::Result::ERROR_FORMAT_NOT_SUPPORTED.into());
        }
        let extra=if a[8]==u64::MAX {words64(m,a[7],3)?}else{vec![a[7],a[8],0]};
        let formats: Vec<_> = words32(m, extra[0], bounded(extra[1], 16)?)?
            .into_iter()
            .map(view_format)
            .collect::<Result<_>>()?;
        let p = self.native_image_limits(
            format(a[1])?,
            ty,
            format_usage(format(a[1])?, a[4])?,
            vk::ImageCreateFlags::from_raw(a[5] as u32),
            &formats,
            vk::ImageTiling::from_raw(a[3] as i32),
            extra[2] as u32,
        )?;
        let mut bytes = Vec::new();
        for n in [
            p.max_extent.width.min(DIMENSION),
            p.max_extent.height.min(DIMENSION),
            p.max_extent.depth.min(DIMENSION),
            p.max_mip_levels.min(DIMENSION.ilog2() + 1),
            p.max_array_layers.min(LAYERS),
            p.sample_counts.as_raw(),
        ] {
            bytes.extend(n.to_le_bytes());
        }
        bytes.extend(
            p.max_resource_size
                .min(self.budget.max_allocation())
                .to_le_bytes(),
        );
        write(m, a[6], &bytes)?;
        if a[9]!=0{
            let mut conversion=vk::SamplerYcbcrConversionImageFormatProperties::default();
            let mut list=vk::ImageFormatListCreateInfo::default().view_formats(&formats);
            let mut info=vk::PhysicalDeviceImageFormatInfo2::default().format(format(a[1])?).ty(ty).tiling(vk::ImageTiling::from_raw(a[3] as i32)).usage(usage(a[4])?).flags(vk::ImageCreateFlags::from_raw(a[5] as u32));
            if !formats.is_empty(){info=info.push_next(&mut list);}
            let mut stencil=vk::ImageStencilUsageCreateInfo::default().stencil_usage(vk::ImageUsageFlags::from_raw(extra[2] as u32));
            if extra[2]!=0{info=info.push_next(&mut stencil);}
            let mut props=vk::ImageFormatProperties2::default().push_next(&mut conversion);
            let owner=self.instance.as_ref().unwrap();let api=ash::khr::get_physical_device_properties2::Instance::new(&owner._entry,&owner.native);
            unsafe{api.get_physical_device_image_format_properties2(self.physical,&info,&mut props)}?;write(m,a[9],&conversion.combined_image_sampler_descriptor_count.to_le_bytes())?;
        }
        Ok(())
    }
    pub(super) fn start_graphics_compile(
        &mut self,
        m: &impl CpuMemory,
        a: [u64; 16],
    ) -> Result<u64> {
        let device = self.device(a[0])?;
        let queues = unsafe {
            device
                .instance
                .native
                .get_physical_device_queue_family_properties(self.physical)
        };
        if !queues[self.family as usize]
            .queue_flags
            .contains(vk::QueueFlags::GRAPHICS)
        {
            return unsupported();
        }
        self.room(1)?;
        output(m, a[7], 8)?;
        let pipeline_layout = self.object(a[1], Kind::PipelineLayout)?;
        let vertex = self.object(a[2], Kind::Shader)?;
        let fragment = if a[3] == 0 {
            if a[14] & 65536 == 0 {
                return invalid();
            }
            None
        } else {
            Some(self.object(a[3], Kind::Shader)?)
        };
        let name = |p| {
            std::ffi::CString::new(guest_string(m, p, 256)?)
                .map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))
        };
        let vertex_name = name(a[4])?;
        let fragment_name = if fragment.is_some() {
            Some(name(a[5])?)
        } else {
            None
        };
        let state = words64(m, a[6], 5)?;
        if std::env::var_os("TRAMES_VULKAN_TRACE").is_some() {
            eprintln!("trames-vulkan graphics-state={state:x?}");
        }
        let mut config = vec![0; 22];
        config[0] = 3; // Older ICDs supply dynamic viewport/scissor only.
        if a[15] != 0 {
            config = words64(m, a[15], 22)?;
        }
        if std::env::var_os("TRAMES_VULKAN_TRACE").is_some() {
            eprintln!("trames-vulkan graphics-config={config:x?}");
        }
        let pass = self.object(state[0], Kind::RenderPass)?;
        let subpass_index=if config[0]&32768!=0 {words64(m,a[6]+40,1)?[0] as usize}else{0};
        let subpass=pass.pass.get().unwrap().subpasses.get(subpass_index).ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
        if !matches!(state[1], 0..=5) || state[2] & !3 != 0 || state[3] > 1 || state[4] & !15 != 0 {
            return unsupported();
        }
        if state[1] == 5 && device.portability.is_some_and(|p| p.triangle_fans == 0) {
            return unsupported();
        }
        if a[12] > 1 || a[12] != 0 && !matches!(state[1], 2 | 4 | 5) {
            return unsupported();
        }
        let restart = a[12] != 0;
        if a[14] & !0x3f773 != 0 {
            return unsupported();
        }
        let polygon = ((a[14] >> 8) & 3) as i32;
        let logic = a[14] & 1024 != 0;
        if polygon > 2
            || polygon != 0 && device.features.fill_mode_non_solid == 0
            || logic && device.features.logic_op == 0
        {
            return unsupported();
        }
        if polygon == 2 && device.portability.is_some_and(|p| p.point_polygons == 0) {
            return unsupported();
        }
        let logic_op = ((a[14] >> 12) & 15) as i32;
        let depth_test = a[14] & 1 != 0;
        let depth_write = a[14] & 2 != 0;
        let compare = ((a[14] >> 4) & 7) as i32;
        if (depth_test || depth_write) && subpass.depth.is_none() {
            return invalid();
        }
        let cache = if a[13] == 0 {
            None
        } else {
            Some(self.object(a[13], Kind::PipelineCache)?)
        };
        let raw_cache = cache.as_ref().map_or(vk::PipelineCache::null(), |c| {
            vk::PipelineCache::from_raw(c.raw)
        });
        let limits = unsafe {
            device
                .instance
                .native
                .get_physical_device_properties(self.physical)
        }
        .limits;
        // Extended graphics state is copied before the asynchronous native
        // compiler starts; no guest pointers enter that worker.
        if config[0] & !65535 != 0 {
            return unsupported();
        }
        let sample_mask = if config[0] & 4096 != 0 {
            u32::try_from(config[11]).map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?
        } else {
            u32::MAX
        };
        let samples = if config[0] & 16384 != 0 { sample_count(config[13])? } else { vk::SampleCountFlags::TYPE_1 };
        let pass_samples = subpass.samples;
        if !pass_samples.is_empty() && pass_samples != samples
            || pass_samples.is_empty() && !limits.framebuffer_no_attachments_sample_counts.contains(samples)
        { return invalid(); }
        let alpha_coverage = config[0] & 16384 != 0 && config[15] != 0;
        let alpha_one = config[0] & 16384 != 0 && config[16] != 0;
        if config[0] & 16384 != 0 && (config[14] > u32::MAX as u64 || config[15] > 1 || config[16] > 1)
            || alpha_one && device.features.alpha_to_one == 0 { return unsupported(); }
        let sample_shading = config[0] & 8192 != 0;
        let min_sample_shading = if sample_shading {
            let value = f32::from_bits(
                u32::try_from(config[12]).map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?,
            );
            if device.features.sample_rate_shading == 0 || !(0.0..=1.0).contains(&value) {
                return unsupported();
            }
            value
        } else {
            0.0
        };
        // Fixed tail after the largest extended blend array. Old callers have
        // no tail and keep stencil disabled. Copy all values before spawning.
        let stencil = if config[0] & 1024 != 0 {
            words64(
                m,
                a[15]
                    .checked_add((23 + MAX_COLORS as u64 * 8) * 8)
                    .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?,
                15,
            )?
        } else {
            vec![0; 15]
        };
        if stencil[0] > 1 {
            return invalid();
        }
        let front = stencil_state(&stencil[1..8])?;
        let back = stencil_state(&stencil[8..15])?;
        let blend_wire = if config[0] & 512 != 0 {
            let count = words64(m, a[15] + 22 * 8, 1)?[0];
            words64(m, a[15] + 23 * 8, bounded(count, MAX_COLORS)? * 8)?
        } else {
            let mut wire = config[11..18].to_vec();
            wire.push(state[4]);
            wire
        };
        if blend_wire.len() / 8 != subpass.color_count {
            return invalid();
        }
        if device.features.independent_blend == 0
            && blend_wire.chunks_exact(8).any(|v| v != &blend_wire[..8])
        {
            return unsupported();
        }
        let mut attachments = Vec::new();
        for v in blend_wire.chunks_exact(8) {
            if v[0] > 1
                || [1, 2, 4, 5].iter().any(|&i| v[i] > 14)
                || v[3] > 4
                || v[6] > 4
                || v[7] & !15 != 0
            {
                return unsupported();
            }
            if v[0] != 0
                && device
                    .portability
                    .is_some_and(|p| p.constant_alpha_color_blend_factors == 0)
                && v[1..3].iter().any(|f| matches!(f, 12 | 13))
            {
                return unsupported();
            }
            attachments.push(
                vk::PipelineColorBlendAttachmentState::default()
                    .blend_enable(v[0] != 0)
                    .src_color_blend_factor(vk::BlendFactor::from_raw(v[1] as i32))
                    .dst_color_blend_factor(vk::BlendFactor::from_raw(v[2] as i32))
                    .color_blend_op(vk::BlendOp::from_raw(v[3] as i32))
                    .src_alpha_blend_factor(vk::BlendFactor::from_raw(v[4] as i32))
                    .dst_alpha_blend_factor(vk::BlendFactor::from_raw(v[5] as i32))
                    .alpha_blend_op(vk::BlendOp::from_raw(v[6] as i32))
                    .color_write_mask(vk::ColorComponentFlags::from_raw(v[7] as u32)),
            );
        }
        let static_states = (!config[0] & 3) as u8;
        let mut static_viewports = Vec::new();
        let mut static_scissors = Vec::new();
        if static_states & 1 != 0 {
            let v: Vec<_> = config[1..7]
                .iter()
                .map(|&v| f32::from_bits(v as u32))
                .collect();
            if !valid_viewport(
                &v,
                device.maintenance1,
                device.viewport_dimensions,
                device.viewport_bounds,
            ) {
                return invalid();
            }
            static_viewports.push(vk::Viewport {
                x: v[0],
                y: v[1],
                width: v[2],
                height: v[3],
                min_depth: v[4],
                max_depth: v[5],
            });
        }
        if static_states & 2 != 0 {
            if config[9] == 0
                || config[10] == 0
                || config[7]
                    .checked_add(config[9])
                    .is_none_or(|n| n > DIMENSION as u64)
                || config[8]
                    .checked_add(config[10])
                    .is_none_or(|n| n > DIMENSION as u64)
            {
                return invalid();
            }
            static_scissors.push(vk::Rect2D {
                offset: vk::Offset2D {
                    x: config[7] as i32,
                    y: config[8] as i32,
                },
                extent: vk::Extent2D {
                    width: config[9] as u32,
                    height: config[10] as u32,
                },
            });
        }
        let binding_stride = if config[0] & 2048 != 0 { 4 } else { 3 };
        let binding_wire = words64(m, a[8], bounded(a[9], 16)? * binding_stride)?;
        let attribute_wire = words64(m, a[10], bounded(a[11], 16)? * 4)?;
        let mut bindings = Vec::new();
        let mut divisors = Vec::new();
        let mut attributes = Vec::new();
        let mut inputs = BTreeMap::new();
        let mut locations = std::collections::BTreeSet::new();
        for x in binding_wire.chunks_exact(binding_stride) {
            if x[0] >= 16.min(limits.max_vertex_input_bindings) as u64
                || x[1] > 2048.min(limits.max_vertex_input_binding_stride) as u64
                || x[2] > 1
                || inputs.contains_key(&(x[0] as u32))
            {
                return unsupported();
            }
            let divisor = if binding_stride == 4 { x[3] } else { 1 };
            validate_divisor(x[2] == 1, divisor, device.divisor)?;
            if divisor != 1 {
                divisors.push(vk::VertexInputBindingDivisorDescriptionEXT {
                    binding: x[0] as u32,
                    divisor: divisor as u32,
                });
            }
            bindings.push(vk::VertexInputBindingDescription {
                binding: x[0] as u32,
                stride: x[1] as u32,
                input_rate: vk::VertexInputRate::from_raw(x[2] as i32),
            });
            inputs.insert(
                x[0] as u32,
                VertexBinding {
                    binding: x[0] as u32,
                    stride: x[1] as u32,
                    instance: x[2] == 1,
                    divisor: divisor as u32,
                    extent: 0,
                },
            );
        }
        for x in attribute_wire.chunks_exact(4) {
            let size =
                vertex_size(x[2]).ok_or(Failure::Vk(vk::Result::ERROR_FORMAT_NOT_SUPPORTED))?;
            if x[0] >= 16.min(limits.max_vertex_input_attributes) as u64
                || x[1] > u32::MAX as u64
                || x[3] > 2047.min(limits.max_vertex_input_attribute_offset) as u64
                || !locations.insert(x[0])
            {
                return unsupported();
            }
            let input = inputs
                .get_mut(&(x[1] as u32))
                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
            let format = vk::Format::from_raw(x[2] as i32);
            let features = unsafe {
                device
                    .instance
                    .native
                    .get_physical_device_format_properties(self.physical, format)
            };
            if !features
                .buffer_features
                .contains(vk::FormatFeatureFlags::VERTEX_BUFFER)
            {
                return Err(vk::Result::ERROR_FORMAT_NOT_SUPPORTED.into());
            }
            if device
                .portability
                .is_some_and(|p| p.vertex_attribute_access_beyond_stride == 0)
                && x[3] + size as u64 > input.stride as u64
            {
                return unsupported();
            }
            input.extent = input.extent.max(x[3] as u32 + size);
            attributes.push(vk::VertexInputAttributeDescription {
                location: x[0] as u32,
                binding: x[1] as u32,
                format,
                offset: x[3] as u32,
            });
        }
        let inputs = inputs.into_values().collect();
        let (raw_layout, raw_vertex, raw_fragment, raw_pass) = (
            vk::PipelineLayout::from_raw(pipeline_layout.raw),
            vk::ShaderModule::from_raw(vertex.raw),
            fragment.as_ref().map(|f| vk::ShaderModule::from_raw(f.raw)),
            vk::RenderPass::from_raw(pass.raw),
        );
        let permit = self
            .budget
            .compile()
            .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        let task = crate::task::Task::spawn(move || {
            let _permit = permit;
            let mut stages = vec![vk::PipelineShaderStageCreateInfo::default()
                .stage(vk::ShaderStageFlags::VERTEX)
                .module(raw_vertex)
                .name(&vertex_name)];
            if let Some((module, name)) = raw_fragment.zip(fragment_name.as_ref()) {
                stages.push(
                    vk::PipelineShaderStageCreateInfo::default()
                        .stage(vk::ShaderStageFlags::FRAGMENT)
                        .module(module)
                        .name(name),
                );
            }
            let mut divisor = vk::PipelineVertexInputDivisorStateCreateInfoEXT::default()
                .vertex_binding_divisors(&divisors);
            let mut vertex = vk::PipelineVertexInputStateCreateInfo::default()
                .vertex_binding_descriptions(&bindings)
                .vertex_attribute_descriptions(&attributes);
            if !divisors.is_empty() {
                vertex = vertex.push_next(&mut divisor);
            }
            let assembly = vk::PipelineInputAssemblyStateCreateInfo::default()
                .topology(vk::PrimitiveTopology::from_raw(state[1] as i32))
                .primitive_restart_enable(restart);
            let mut viewport = vk::PipelineViewportStateCreateInfo::default()
                .viewport_count(1)
                .scissor_count(1);
            if !static_viewports.is_empty() {
                viewport = viewport.viewports(&static_viewports);
            }
            if !static_scissors.is_empty() {
                viewport = viewport.scissors(&static_scissors);
            }
            let raster = vk::PipelineRasterizationStateCreateInfo::default()
                .rasterizer_discard_enable(a[14] & 65536 != 0)
                .depth_bias_enable(a[14] & 131072 != 0)
                .polygon_mode(vk::PolygonMode::from_raw(polygon))
                .cull_mode(vk::CullModeFlags::from_raw(state[2] as u32))
                .front_face(vk::FrontFace::from_raw(state[3] as i32))
                .line_width(1.0);
            let multisample = vk::PipelineMultisampleStateCreateInfo::default()
                .rasterization_samples(samples)
                .alpha_to_coverage_enable(alpha_coverage)
                .alpha_to_one_enable(alpha_one)
                .sample_shading_enable(sample_shading)
                .min_sample_shading(min_sample_shading);
            let sample_masks = [sample_mask, if config[0] & 16384 != 0 { config[14] as u32 } else { u32::MAX }];
            let multisample = multisample.sample_mask(&sample_masks);
            let depth = vk::PipelineDepthStencilStateCreateInfo::default()
                .depth_test_enable(depth_test)
                .depth_write_enable(depth_write)
                .depth_compare_op(vk::CompareOp::from_raw(compare))
                .stencil_test_enable(stencil[0] != 0)
                .front(front)
                .back(back);
            let blend = vk::PipelineColorBlendStateCreateInfo::default()
                .logic_op_enable(logic)
                .logic_op(vk::LogicOp::from_raw(logic_op))
                .attachments(&attachments)
                .blend_constants(std::array::from_fn(|i| {
                    f32::from_bits(config[18 + i] as u32)
                }));
            let mut dynamic_states = Vec::new();
            if static_states & 1 == 0 {
                dynamic_states.push(vk::DynamicState::VIEWPORT);
            }
            if static_states & 2 == 0 {
                dynamic_states.push(vk::DynamicState::SCISSOR);
            }
            for state in 2..=8 {
                if config[0] & (1 << state) != 0 {
                    dynamic_states.push(vk::DynamicState::from_raw(state));
                }
            }
            let dynamic =
                vk::PipelineDynamicStateCreateInfo::default().dynamic_states(&dynamic_states);
            let info = [vk::GraphicsPipelineCreateInfo::default()
                .stages(&stages)
                .vertex_input_state(&vertex)
                .input_assembly_state(&assembly)
                .viewport_state(&viewport)
                .rasterization_state(&raster)
                .multisample_state(&multisample)
                .depth_stencil_state(&depth)
                .color_blend_state(&blend)
                .dynamic_state(&dynamic)
                .layout(raw_layout)
                .render_pass(raw_pass)
                .subpass(subpass_index as u32)];
            match unsafe {
                device
                    .native
                    .create_graphics_pipelines(raw_cache, &info, None)
            } {
                Ok(p) => Ok(CompiledPipeline { device, raw: p[0] }),
                Err((pipelines, error)) => {
                    for p in pipelines {
                        unsafe {
                            device.native.destroy_pipeline(p, None);
                        }
                    }
                    Err(error)
                }
            }
        })
        .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        let job = self.id();
        self.compiles.insert(
            job,
            Compile {
                task,
                dependencies: {
                    let mut d = vec![pipeline_layout, pass, vertex];
                    d.extend(fragment);
                    d.extend(cache);
                    d
                },
                bind_point: vk::PipelineBindPoint::GRAPHICS,
                creation_flags: 0,
                subpass: subpass_index as u32,
                vertex_inputs: inputs,
                static_states,
                output: a[7],
                abandoned: false,
            },
        );
        Ok(job)
    }
    pub(super) fn image_barriers(
        &self,
        m: &impl CpuMemory,
        command: &Rc<Object>,
        address: u64,
        count: u64,
        stride: u64,
    ) -> Result<Vec<vk::ImageMemoryBarrier<'static>>> {
        let stride = match stride {
            0 => 5,
            6 => 6,
            10 => 10,
            _ => return unsupported(),
        };
        let wire = words64(m, address, bounded(count, 64)? * stride)?;
        let mut barriers = Vec::new();
        let mut dependencies = Vec::new();
        for b in wire.chunks_exact(stride) {
            let image = self.object(b[0], Kind::Image)?;
            if image.deps.borrow().is_empty()
                && image.swapchain.borrow().is_none()
                && image.wayland_pool.borrow().is_none()
            {
                return invalid();
            }
            if image.kind != Kind::SwapchainImage && (b[3] == 1000001002 || b[4] == 1000001002) {
                return invalid();
            }
            let s = shape(&image)?;
            let range = if stride == 10 {
                s.range(&b[5..10])?
            } else {
                let mut r = s.whole();
                if stride == 6 {
                    r = s.range(&[b[5], 0, s.mips as u64, 0, s.layers as u64])?;
                }
                r
            };
            // Independent packed depth/stencil transitions require the same
            // original native feature selected at device creation.
            if range.aspect_mask != s.aspect() && command.device.compute_features&compute::SEPARATE_DEPTH_STENCIL_LAYOUTS==0 {
                return unsupported();
            }
            barriers.push(
                vk::ImageMemoryBarrier::default()
                    .image(vk::Image::from_raw(image.raw))
                    .src_access_mask(vk::AccessFlags::from_raw(b[1] as u32))
                    .dst_access_mask(vk::AccessFlags::from_raw(b[2] as u32))
                    .old_layout(self.native_layout(b[3], true)?)
                    .new_layout(self.native_layout(b[4], false)?)
                    .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                    .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                    .subresource_range(range),
            );
            dependencies.push(image);
        }
        for image in dependencies {
            command.retain(image);
        }
        Ok(barriers)
    }
    pub(super) fn graphics_call(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let device = self.device.as_ref().unwrap().clone();
        let d = &device.native;
        match op {
            217 => self.render_graph(m,a)?,
            60 => {
                self.room(1)?;
                output(m, a[5], 8)?;
                let f = format(a[1])?;
                let u = format_usage(f, a[4])?;
                // a[11] != 0 identifies the extended shape, preserving the old
                // 2D one-level wire used by existing native-call clients.
                let s = if a[11] == 0 {
                    ImageShape::d2(a[2] as u32, a[3] as u32, f)
                } else {
                    if a[10..=13].iter().any(|&v| v > u32::MAX as u64) {
                        return invalid();
                    }
                    ImageShape {
                        width: a[2] as u32,
                        height: a[3] as u32,
                        format: f,
                        ty: image_type(a[10])?,
                        depth: a[11] as u32,
                        mips: a[12] as u32,
                        layers: a[13] as u32,
                        samples: sample_count(a[14].max(1))?,
                        tiling: match a[15] {0=>vk::ImageTiling::OPTIMAL,1=>vk::ImageTiling::LINEAR,_=>return unsupported()},
                    }
                };
                if a[2] > u32::MAX as u64 || a[3] > u32::MAX as u64 {
                    return invalid();
                }
                validate_shape(s, a[9])?;
                if s.samples != vk::SampleCountFlags::TYPE_1 && u.contains(vk::ImageUsageFlags::STORAGE) { return unsupported(); }
                if a[9] & 32 != 0
                    && device
                        .portability
                        .is_some_and(|p| p.image_view2_d_on3_d_image == 0)
                {
                    return unsupported();
                }
                let extra=if a[8]==u64::MAX {words64(m,a[7],3)?}else{vec![a[7],a[8],0]};
        let formats: Vec<_> = words32(m, extra[0], bounded(extra[1], 16)?)?
                    .into_iter()
                    .map(view_format)
                    .collect::<Result<_>>()?;
                if !formats.is_empty() && !device.format_list {
                    return unsupported();
                }
                let limits = self.native_image_limits(
                    f,
                    s.ty,
                    u,
                    vk::ImageCreateFlags::from_raw(a[9] as u32),
                    &formats,
                    s.tiling,
                    extra[2] as u32,
                )?;
                if s.width > limits.max_extent.width
                    || s.height > limits.max_extent.height
                    || s.depth > limits.max_extent.depth
                    || s.mips > limits.max_mip_levels
                    || s.layers > limits.max_array_layers
                    || !limits.sample_counts.contains(s.samples)
                {
                    return invalid();
                }
                let mut list = vk::ImageFormatListCreateInfo::default().view_formats(&formats);
                if a[9] & !0x138 != 0
                    || a[9] & 256 != 0 && !device.maintenance2
                    || a[9] & 32 != 0 && !device.maintenance1
                {
                    return unsupported();
                }
                let mut stencil=vk::ImageStencilUsageCreateInfo::default().stencil_usage(vk::ImageUsageFlags::from_raw(extra[2] as u32));
                let mut info = vk::ImageCreateInfo::default()
                    .flags(vk::ImageCreateFlags::from_raw(a[9] as u32))
                    .image_type(s.ty)
                    .format(f)
                    .extent(vk::Extent3D {
                        width: a[2] as u32,
                        height: a[3] as u32,
                        depth: s.depth,
                    })
                    .mip_levels(s.mips)
                    .array_layers(s.layers)
                    .samples(s.samples)
                    .tiling(s.tiling)
                    .usage(u)
                    .sharing_mode(vk::SharingMode::EXCLUSIVE)
                    .initial_layout(match a[6] {
                        0 => vk::ImageLayout::UNDEFINED,
                        8 => vk::ImageLayout::PREINITIALIZED,
                        _ => return invalid(),
                    });
                if !formats.is_empty() {
                    info = info.push_next(&mut list);
                }
                if extra[2]!=0{usage(extra[2])?;info=info.push_next(&mut stencil);}
                let raw = unsafe { d.create_image(&info, None) }?;
                let id = self.put(Kind::Image, raw.as_raw(), vec![], 0, u.as_raw());
                self.objects[&id].image_flags.set(a[9] as u32);
                self.objects[&id].image.set(Some(s));
                self.objects[&id].stencil_usage.set(extra[2] as u32);
                self.publish(m, a[5], id)?;
            }
            61 => self.remove(a[1], Kind::Image)?,
            62 => {
                let image = self.object(a[1], Kind::Image)?;
                if image.kind == Kind::SwapchainImage {
                    return invalid();
                }
                let r = unsafe { d.get_image_memory_requirements(vk::Image::from_raw(image.raw)) };
                let mut bytes = Vec::new();
                bytes.extend(r.size.to_le_bytes());
                bytes.extend(r.alignment.to_le_bytes());
                bytes.extend(r.memory_type_bits.to_le_bytes());
                bytes.extend([0; 4]);
                write(m, a[2], &bytes)?;
            }
            63 => {
                let image = self.object(a[1], Kind::Image)?;
                let memory = self.object(a[2], Kind::Memory)?;
                if image.kind == Kind::SwapchainImage {
                    return invalid();
                }
                let r = unsafe { d.get_image_memory_requirements(vk::Image::from_raw(image.raw)) };
                if image.swapchain.borrow().is_some()
                    || image.wayland_pool.borrow().is_some()
                    || !image.deps.borrow().is_empty()
                    || !a[3].is_multiple_of(r.alignment)
                    || r.memory_type_bits & (1u32 << memory.state.get()) == 0
                    || a[3].checked_add(r.size).is_none_or(|n| n > memory.size)
                {
                    return invalid();
                }
                unsafe {
                    d.bind_image_memory(
                        vk::Image::from_raw(image.raw),
                        vk::DeviceMemory::from_raw(memory.raw),
                        a[3],
                    )
                }?;
                image.memory_binding.set(Some(coherent::Binding {
                    memory: a[2],
                    offset: a[3],
                    size: r.size,
                }));
                image.retain(memory);
            }
            64 => {
                self.room(1)?;
                output(m, a[3], 8)?;
                let image = self.object(a[1], Kind::Image)?;
                let mut shape = shape(&image)?;
                let view_format = format(a[2])?;
                let wire=if a[7]==0{vec![shape.aspect().as_raw() as u64,0,1,0,1]}else{words64(m,a[7],5)?};
                let plane=ycbcr::plane(shape.format.as_raw() as u64,wire[0]);
                let stencil_usage=image.stencil_usage.get();
                let effective_usage=if stencil_usage==0 || wire[0]&4==0{image.flags}else if wire[0]&2==0{stencil_usage}else{image.flags&stencil_usage};
                if view_format != shape.format
                    && (image.image_flags.get() & 8 == 0
                        || is_depth_stencil(view_format)
                        || is_depth_stencil(shape.format)
                        || if let Some((f,_,_))=plane {view_format.as_raw() as u64!=f}else{block_layout(view_format.as_raw() as u64)
                            != block_layout(shape.format.as_raw() as u64)})
                    || image.deps.borrow().is_empty()
                        && image.swapchain.borrow().is_none()
                        && image.wayland_pool.borrow().is_none()
                {
                    return invalid();
                }
                let source_shape=shape;
                let view_usage = if a[4] == 0 {
                    vk::ImageUsageFlags::empty()
                } else {
                    if !device.maintenance2 {
                        return unsupported();
                    }
                    let usage = usage(a[4])?;
                    if usage.as_raw() & !effective_usage != 0 {
                        return invalid();
                    }
                    usage
                };
                let mut view_usage_info = vk::ImageViewUsageCreateInfo::default().usage(view_usage);
                // Wire type zero is the legacy 2D default; new callers can
                // request a one-layer array view and ordinary native swizzles.
                let view_type = if a[7] == 0 && a[5] == 0 {
                    vk::ImageViewType::TYPE_2D
                } else if a[5] <= 6 {
                    vk::ImageViewType::from_raw(a[5] as i32)
                } else {
                    return unsupported();
                };

                let volume_slice = shape.ty == vk::ImageType::TYPE_3D
                    && matches!(
                        view_type,
                        vk::ImageViewType::TYPE_2D | vk::ImageViewType::TYPE_2D_ARRAY
                    );
                let mut range_shape = shape;
                if volume_slice {
                    if device
                        .portability
                        .is_some_and(|p| p.image_view2_d_on3_d_image == 0)
                    {
                        return unsupported();
                    }
                    range_shape.layers = shape.extent(wire[1])?[2];
                }
                let range = range_shape.range(&wire)?;
                validate_view(shape, image.image_flags.get(), view_type, range)?;
                if view_type == vk::ImageViewType::CUBE_ARRAY
                    && device.features.image_cube_array == 0
                {
                    return unsupported();
                }
                if a[6] > 0xffff || (0..4).any(|i| (a[6] >> (i * 4)) & 15 > 6) {
                    return unsupported();
                }
                if device
                    .portability
                    .is_some_and(|p| p.image_view_format_swizzle == 0)
                    && (0..4).any(|i| {
                        let v = (a[6] >> (i * 4)) & 15;
                        v != 0 && v != i + 3
                    })
                {
                    return unsupported();
                }
                let component =
                    |i: u32| vk::ComponentSwizzle::from_raw(((a[6] >> (i * 4)) & 15u64) as i32);
                let mut info = vk::ImageViewCreateInfo::default()
                    .components(vk::ComponentMapping {
                        r: component(0),
                        g: component(1),
                        b: component(2),
                        a: component(3),
                    })
                    .image(vk::Image::from_raw(image.raw))
                    .view_type(view_type)
                    .format(shape.format)
                    .subresource_range(range);
                if a[4] != 0 {
                    info = info.push_next(&mut view_usage_info);
                }
                info.format=view_format;
                let conversion=if a[8]!=0{Some(self.object(a[8],Kind::YcbcrConversion)?)}else{None};
                let mut conversion_info=vk::SamplerYcbcrConversionInfo::default();
                if let Some(value)=&conversion {if value.size!=a[2]{return invalid();}conversion_info.conversion=vk::SamplerYcbcrConversion::from_raw(value.raw);info=info.push_next(&mut conversion_info);}
                let raw = unsafe { d.create_image_view(&info, None) }?;
                let id = self.put(
                    Kind::ImageView,
                    raw.as_raw(),
                    std::iter::once(image).chain(conversion).collect(),
                    if view_usage.is_empty(){effective_usage as u64}else{view_usage.as_raw() as u64},
                    range.aspect_mask.as_raw(),
                );
                shape.format=view_format;
                let mut extent = source_shape.extent(range.base_mip_level as u64)?;
                if let Some((_,x,y))=plane{extent[0]=extent[0].div_ceil(x);extent[1]=extent[1].div_ceil(y);}
                shape.width = extent[0];
                shape.height = extent[1];
                shape.depth = extent[2];
                shape.mips = range.level_count;
                shape.layers = range.layer_count;
                if volume_slice {
                    shape.ty = vk::ImageType::TYPE_2D;
                    shape.depth = 1;
                }
                self.objects[&id].image.set(Some(shape));
                self.publish(m, a[3], id)?;
            }
            65 => self.remove(a[1], Kind::ImageView)?,
            66 | 122 => {
                if op == 122 && !device.renderpass2 {
                    return unsupported();
                }
                self.room(1)?;
                output(m, a[8], 8)?;
                let extras = if a[15] != 0 { words64(m,a[15],16)? } else { vec![0;16] };
                let view_mask = u32::try_from(extras[0]).map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                if view_mask != 0 && (device.compute_features & compute::MULTIVIEW == 0
                    || 32 - view_mask.leading_zeros() > self.capabilities.compute.multiview_count()) { return unsupported(); }
                let correlations = words32(m, extras[2], bounded(extras[1],32)?)?;
                let view_offsets = if extras[3] == 0 { vec![0; a[7] as usize] } else { words32(m,extras[3],bounded(a[7],8)?)? };
                let (mut pass, attachments, references, depth_reference, resolves) = if a[14] != 0 {
                    render_pass::decode(self, m, a[14])?
                } else {
                    let layouts = if a[13] == 0 {
                        vec![2, 2, 2, 2, 2, 2, 2, 2, 3]
                    } else {
                        words64(m, a[13], 9)?
                    };
                    let colors = if a[10] == 0 {
                        vec![a[1], a[2], a[3], a[4], a[5]]
                    } else {
                        words64(m, a[10], bounded(a[11], MAX_COLORS)? * 5)?
                    };
                    let count = colors.len() / 5;
                    if count > device.max_color_attachments as usize { return unsupported(); }
                    let mut pass = PassInfo::new(count);
                    let mut attachments = Vec::new();
                    let mut references = Vec::new();
                    for (slot, x) in colors.chunks_exact(5).enumerate() {
                        if x[0] == 0 {
                            references.push(
                                vk::AttachmentReference::default()
                                    .attachment(vk::ATTACHMENT_UNUSED)
                                    .layout(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL),
                            );
                            continue;
                        }
                        let index = attachments.len();
                        let f = format(x[0])?;
                        if is_depth_stencil(f) || x[1] > 2 || x[2] > 1 {
                            return unsupported();
                        }
                        pass.colors[slot] = f;
                        if x[1] == 1 {
                            pass.clear_count = pass.clear_count.max(index+1);
                        }
                        attachments.push(
                            vk::AttachmentDescription::default()
                                .format(f)
                                .samples(vk::SampleCountFlags::TYPE_1)
                                .load_op(vk::AttachmentLoadOp::from_raw(x[1] as i32))
                                .store_op(vk::AttachmentStoreOp::from_raw(x[2] as i32))
                                .stencil_load_op(vk::AttachmentLoadOp::DONT_CARE)
                                .stencil_store_op(vk::AttachmentStoreOp::DONT_CARE)
                                .initial_layout(self.native_layout(x[3], true)?)
                                .final_layout(self.native_layout(x[4], false)?),
                        );
                        references.push(
                            vk::AttachmentReference::default()
                                .attachment(index as u32)
                                .layout(attachment_reference_layout(layouts[slot], false)?),
                        );
                    }
                    let used_colors = attachments.len();
                    let depth_reference = vk::AttachmentReference::default()
                        .attachment(used_colors as u32)
                        .layout(attachment_reference_layout(layouts[8], true)?);
                    if a[9] != 0 {
                        if a[12] > 1 {
                            return unsupported();
                        }
                        let mut x = words64(m, a[9], if a[12] == 1 { 7 } else { 5 })?;
                        if a[12] == 0 {
                            x.extend([2, 1]); // Legacy wire: stencil DONT_CARE.
                        }
                        let f = format(x[0])?;
                        if !is_depth_stencil(f) || x[1] > 2 || x[2] > 1 || x[5] > 2 || x[6] > 1 {
                            return unsupported();
                        }
                        pass.depth = Some(f);
                        let aspects = format_aspects(f);
                        if aspects.contains(vk::ImageAspectFlags::DEPTH) && x[1] == 1
                            || aspects.contains(vk::ImageAspectFlags::STENCIL) && x[5] == 1
                        {
                            pass.clear_count = pass.clear_count.max(used_colors+1);
                        }
                        attachments.push(
                            vk::AttachmentDescription::default()
                                .format(f)
                                .samples(vk::SampleCountFlags::TYPE_1)
                                .load_op(vk::AttachmentLoadOp::from_raw(x[1] as i32))
                                .store_op(vk::AttachmentStoreOp::from_raw(x[2] as i32))
                                .stencil_load_op(vk::AttachmentLoadOp::from_raw(x[5] as i32))
                                .stencil_store_op(vk::AttachmentStoreOp::from_raw(x[6] as i32))
                                .initial_layout(self.native_layout(x[3], true)?)
                                .final_layout(self.native_layout(x[4], false)?),
                        );
                    }
                    (pass, attachments, references, depth_reference, Vec::new())
                };
                pass.view_mask = view_mask;
                pass.subpasses[0].view_mask = view_mask;
                pass.attachments = attachments.len();
                for (i, x) in attachments.iter().enumerate() {
                    pass.formats[i] = x.format;
                    pass.sample_counts[i] = x.samples;
                }
                if pass.color_count > device.max_color_attachments as usize { return unsupported(); }
                for r in references.iter().chain(resolves.iter()) {
                    if r.attachment != vk::ATTACHMENT_UNUSED { pass.usages[r.attachment as usize] |= vk::ImageUsageFlags::COLOR_ATTACHMENT; }
                }
                if pass.depth.is_some() { pass.usages[depth_reference.attachment as usize] |= vk::ImageUsageFlags::DEPTH_STENCIL_ATTACHMENT; }
                for r in references.iter().chain(pass.depth.is_some().then_some(&depth_reference)) {
                    if r.attachment == vk::ATTACHMENT_UNUSED { continue; }
                    let samples = attachments[r.attachment as usize].samples;
                    if !pass.samples.is_empty() && pass.samples != samples { return invalid(); }
                    pass.samples = samples;
                }
                let wire = words64(m, a[6], bounded(a[7], 8)? * 7)?;
                let mut dependencies = Vec::new();
                for x in wire.chunks_exact(7) {
                    if !matches!(x[0], 0 | 0xffffffff)
                        || !matches!(x[1], 0 | 0xffffffff)
                        || x[6] & !7 != 0
                    {
                        return unsupported();
                    }
                    dependencies.push(
                        vk::SubpassDependency::default()
                            .src_subpass(x[0] as u32)
                            .dst_subpass(x[1] as u32)
                            .src_stage_mask(device.stage(x[2] as u32)?)
                            .dst_stage_mask(device.stage(x[3] as u32)?)
                            .src_access_mask(vk::AccessFlags::from_raw(x[4] as u32))
                            .dst_access_mask(vk::AccessFlags::from_raw(x[5] as u32))
                            .dependency_flags(vk::DependencyFlags::from_raw(x[6] as u32)),
                    );
                }
                let raw = if op == 122 {
                    let attachments: Vec<_> = attachments
                        .iter()
                        .map(|x| {
                            vk::AttachmentDescription2::default()
                                .format(x.format)
                                .samples(x.samples)
                                .load_op(x.load_op)
                                .store_op(x.store_op)
                                .stencil_load_op(x.stencil_load_op)
                                .stencil_store_op(x.stencil_store_op)
                                .initial_layout(x.initial_layout)
                                .final_layout(x.final_layout)
                        })
                        .collect();
                    let references: Vec<_> = references
                        .iter()
                        .map(|x| {
                            vk::AttachmentReference2::default()
                                .attachment(x.attachment)
                                .layout(x.layout)
                                .aspect_mask(vk::ImageAspectFlags::COLOR)
                        })
                        .collect();
                    let depth_reference = vk::AttachmentReference2::default()
                        .attachment(depth_reference.attachment)
                        .layout(depth_reference.layout)
                        .aspect_mask(
                            pass.depth
                                .map_or(vk::ImageAspectFlags::empty(), format_aspects),
                        );
                    let resolves: Vec<_> = resolves.iter().map(|r| vk::AttachmentReference2::default()
                        .attachment(r.attachment).layout(r.layout).aspect_mask(vk::ImageAspectFlags::COLOR)).collect();
                    let mut subpass = vk::SubpassDescription2::default()
                        .pipeline_bind_point(vk::PipelineBindPoint::GRAPHICS)
                        .view_mask(view_mask)
                        .color_attachments(&references);
                    if pass.depth.is_some() { subpass = subpass.depth_stencil_attachment(&depth_reference); }
                    if !resolves.is_empty() { subpass = subpass.resolve_attachments(&resolves); }
                    let subpasses = [subpass];
                    let dependencies: Vec<_> = dependencies
                        .iter().enumerate()
                        .map(|(i,x)| {
                            vk::SubpassDependency2::default()
                                .src_subpass(x.src_subpass)
                                .dst_subpass(x.dst_subpass)
                                .src_stage_mask(x.src_stage_mask)
                                .dst_stage_mask(x.dst_stage_mask)
                                .src_access_mask(x.src_access_mask)
                                .dst_access_mask(x.dst_access_mask)
                                .dependency_flags(x.dependency_flags)
                                .view_offset(view_offsets[i] as i32)
                        })
                        .collect();
                    let info = vk::RenderPassCreateInfo2::default()
                        .attachments(&attachments)
                        .subpasses(&subpasses)
                        .dependencies(&dependencies)
                        .correlated_view_masks(&correlations);
                    let api = ash::khr::create_renderpass2::Device::new(&device.instance.native, d);
                    unsafe { api.create_render_pass2(&info, None) }?
                } else {
                    let mut subpass = vk::SubpassDescription::default()
                        .pipeline_bind_point(vk::PipelineBindPoint::GRAPHICS)
                        .color_attachments(&references);
                    if pass.depth.is_some() { subpass = subpass.depth_stencil_attachment(&depth_reference); }
                    if !resolves.is_empty() { subpass = subpass.resolve_attachments(&resolves); }
                    let subpasses = [subpass];
                    let masks=[view_mask];let offsets:Vec<_>=view_offsets.iter().map(|&v|v as i32).collect();
                    let mut multiview=vk::RenderPassMultiviewCreateInfo::default().view_masks(&masks).view_offsets(&offsets).correlation_masks(&correlations);
                    let mut info = vk::RenderPassCreateInfo::default()
                        .attachments(&attachments)
                        .subpasses(&subpasses)
                        .dependencies(&dependencies);
                    if view_mask != 0 { info=info.push_next(&mut multiview); }
                    unsafe { d.create_render_pass(&info, None) }?
                };
                let id = self.put(Kind::RenderPass, raw.as_raw(), vec![], 0, 0);
                self.objects[&id].pass.set(Box::new(pass)).expect("new render pass metadata");
                self.publish(m, a[8], id)?;
            }
            67 => self.remove(a[1], Kind::RenderPass)?,
            68 => {
                self.room(1)?;
                output(m, a[5], 8)?;
                let pass = self.object(a[1], Kind::RenderPass)?;
                let p = pass.pass.get().unwrap();
                let layers = u32::try_from(a[9].max(1)).map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                if p.view_mask != 0 && layers != 1 { return invalid(); }
                let required_layers = if p.view_mask == 0 { layers } else { 32-p.view_mask.leading_zeros() };
                let ids = if a[7] == 0 && a[10] == 0 {
                    let mut ids = vec![a[2]];
                    if a[6] != 0 {
                        ids.push(a[6]);
                    }
                    ids
                } else {
                    descriptors::words(m,a[7],a[8],1)?
                };
                if ids.len() != p.attachment_count()
                    || a[3] == 0
                    || a[4] == 0
                    || a[3] > DIMENSION as u64
                    || a[4] > DIMENSION as u64
                {
                    return invalid();
                }
                let mut attachments = Vec::new();
                let mut dependencies = vec![pass.clone()];
                for (i, id) in ids.into_iter().enumerate() {
                    let view = self.object(id, Kind::ImageView)?;
                    let shape = shape(&view)?;
                    let required = p.attachment_usage(i);
                    if !shape.attachment()
                        || shape.format != p.attachment_format(i)
                        || shape.samples != p.sample_counts[i]
                        || shape.layers < required_layers
                        || a[3] > shape.width as u64
                        || a[4] > shape.height as u64
                        || view.size as u32 & required.as_raw() != required.as_raw()
                    {
                        return invalid();
                    }
                    attachments.push(vk::ImageView::from_raw(view.raw));
                    dependencies.push(view);
                }
                let info = vk::FramebufferCreateInfo::default()
                    .render_pass(vk::RenderPass::from_raw(pass.raw))
                    .attachments(&attachments)
                    .width(a[3] as u32)
                    .height(a[4] as u32)
                    .layers(layers);
                let raw = unsafe { d.create_framebuffer(&info, None) }?;
                let id = self.put(Kind::Framebuffer, raw.as_raw(), dependencies, 0, 0);
                let mut shape=ImageShape::d2(a[3] as u32,a[4] as u32,p.attachment_format(0));shape.layers=layers;
                self.objects[&id].image.set(Some(shape));
                self.publish(m, a[5], id)?;
            }
            125 => {
                if !device.imageless {
                    return unsupported();
                }
                self.room(1)?;
                output(m, a[6], 8)?;
                let pass = self.object(a[1], Kind::RenderPass)?;
                let p = pass.pass.get().unwrap();
                let count = p.attachment_count();
                let layers=u32::try_from(a[7].max(1)).map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                if p.view_mask!=0 && layers!=1 { return invalid(); }
                let required_layers=if p.view_mask==0 {layers} else {32-p.view_mask.leading_zeros()};
                if a[4] != count as u64
                    || a[2] == 0
                    || a[3] == 0
                    || a[2] > DIMENSION as u64
                    || a[3] > DIMENSION as u64
                {
                    return invalid();
                }
                let wire = descriptors::words(m,a[5],count as u64,7)?;
                let mut specs = Vec::new();
                for (i, x) in wire.chunks_exact(7).enumerate() {
                    let u = usage(x[1])?;
                    let wanted = p.attachment_format(i);
                    let required = p.attachment_usage(i);
                    let formats: Vec<_> = words32(m, x[5], bounded(x[6], 16)?)?
                        .into_iter()
                        .map(view_format)
                        .collect::<Result<_>>()?;
                    if x[0] & !0x138 != 0
                        || !u.contains(required)
                        || x[2] < a[2]
                        || x[3] < a[3]
                        || x[2] > DIMENSION as u64
                        || x[3] > DIMENSION as u64
                        || x[4] < required_layers as u64 || x[4] > LAYERS as u64
                        || !formats.contains(&wanted)
                    {
                        return invalid();
                    }
                    specs.push(AttachmentSpec {
                        flags: vk::ImageCreateFlags::from_raw(x[0] as u32),
                        usage: u,
                        width: x[2] as u32,
                        height: x[3] as u32,
                        formats,
                        layers: x[4] as u32,
                    });
                }
                let images: Vec<_> = specs
                    .iter()
                    .map(|s| {
                        vk::FramebufferAttachmentImageInfo::default()
                            .flags(s.flags)
                            .usage(s.usage)
                            .width(s.width)
                            .height(s.height)
                            .layer_count(s.layers)
                            .view_formats(&s.formats)
                    })
                    .collect();
                let mut attachment_info =
                    vk::FramebufferAttachmentsCreateInfo::default().attachment_image_infos(&images);
                let mut info = vk::FramebufferCreateInfo::default()
                    .flags(vk::FramebufferCreateFlags::IMAGELESS)
                    .render_pass(vk::RenderPass::from_raw(pass.raw))
                    .width(a[2] as u32)
                    .height(a[3] as u32)
                    .layers(layers)
                    .push_next(&mut attachment_info);
                info.attachment_count = count as u32;
                let raw = unsafe { d.create_framebuffer(&info, None) }?;
                let id = self.put(Kind::Framebuffer, raw.as_raw(), vec![pass.clone()], 0, 1);
                let mut shape=ImageShape::d2(a[2] as u32,a[3] as u32,p.attachment_format(0));shape.layers=layers;
                self.objects[&id].image.set(Some(shape));
                *self.objects[&id].attachment_specs.borrow_mut() = specs;
                self.publish(m, a[6], id)?;
            }
            69 => self.remove(a[1], Kind::Framebuffer)?,
            71..=76 | 94..=97 | 114 | 123..=124 | 134..=136 | 151 | 215 => {
                let c = self.object(a[1], Kind::CommandBuffer)?;
                if c.state.get() != 1 {
                    return invalid();
                }
                let raw = vk::CommandBuffer::from_raw(c.raw);
                match op {
                    151 => {
                        let recording = c.recording.borrow();
                        let pass = recording
                            .pass
                            .as_ref()
                            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                        let info = &pass.pass.get().unwrap().subpasses[recording.subpass];
                        let area = recording
                            .render_area
                            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                        if a[3] == 0 || a[5] == 0 {
                            return invalid();
                        }
                        let attachments = words64(m, a[2], bounded(a[3], MAX_ATTACHMENTS)? * 6)?
                            .chunks_exact(6)
                            .map(|v| clear_attachment(info, v))
                            .collect::<Result<Vec<_>>>()?;
                        let rects = words64(m, a[4], bounded(a[5], 64)? * 6)?
                            .chunks_exact(6)
                            .map(|v| clear_rectangle(area, v, recording.layers))
                            .collect::<Result<Vec<_>>>()?;
                        // Begin-pass dependencies already retain framebuffer,
                        // views/images/memory through submission completion.
                        unsafe {
                            d.cmd_clear_attachments(raw, &attachments, &rects);
                        }
                    }
                    135 => {
                        let src = self.object(a[2], Kind::Image)?;
                        let dst = self.object(a[4], Kind::Image)?;
                        let src_shape = shape(&src)?;
                        let dst_shape = shape(&dst)?;
                        let src_layout = self.native_layout(a[3], false)?;
                        let dst_layout = self.native_layout(a[5], false)?;
                        if c.recording.borrow().pass.is_some()
                            || a[7] == 0
                            || a[8] > 1
                            || [&src, &dst].iter().any(|i| {
                                i.deps.borrow().is_empty()
                                    && i.swapchain.borrow().is_none()
                                    && i.wayland_pool.borrow().is_none()
                            })
                            || !matches!(
                                src_layout,
                                vk::ImageLayout::GENERAL | vk::ImageLayout::TRANSFER_SRC_OPTIMAL
                            )
                            || !matches!(
                                dst_layout,
                                vk::ImageLayout::GENERAL | vk::ImageLayout::TRANSFER_DST_OPTIMAL
                            )
                            || is_depth_stencil(src_shape.format) && a[8] != 0
                        {
                            return invalid();
                        }
                        let properties = |s: ImageShape| unsafe { device.instance.native.get_physical_device_format_properties(self.physical, s.format) }.optimal_tiling_features;
                        if std::env::var_os("TRAMES_VULKAN_TRACE").is_some() {
                            eprintln!(
                                "trames-vulkan blit src={:?}/{:?} dst={:?}/{:?} filter={} src-features={:?} dst-features={:?}",
                                src_shape.format,
                                src_shape.ty,
                                dst_shape.format,
                                dst_shape.ty,
                                a[8],
                                properties(src_shape),
                                properties(dst_shape)
                            );
                        }
                        let src_flags = vk::FormatFeatureFlags::BLIT_SRC
                            | if a[8] != 0 {
                                vk::FormatFeatureFlags::SAMPLED_IMAGE_FILTER_LINEAR
                            } else {
                                vk::FormatFeatureFlags::empty()
                            };
                        if !properties(src_shape).contains(src_flags)
                            || !properties(dst_shape).contains(vk::FormatFeatureFlags::BLIT_DST)
                        {
                            return unsupported();
                        }
                        let wire = words64(m, a[6], bounded(a[7], 64)? * 20)?;
                        let regions = wire
                            .chunks_exact(20)
                            .map(|r| {if aspect_usage(&src,r[0] as u32)&1==0 || aspect_usage(&dst,r[10] as u32)&2==0{return invalid();}checked_blit(r, src_shape, dst_shape)})
                            .collect::<Result<Vec<_>>>()?;
                        if src.raw == dst.raw
                            && regions.iter().any(|a| {
                                regions.iter().any(|b| {
                                    subresources_overlap(a.src_subresource, b.dst_subresource)
                                        && (src_layout != dst_layout || blit_overlap(a, b))
                                })
                            })
                        {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_blit_image(
                                raw,
                                vk::Image::from_raw(src.raw),
                                src_layout,
                                vk::Image::from_raw(dst.raw),
                                dst_layout,
                                &regions,
                                vk::Filter::from_raw(a[8] as i32),
                            );
                        }
                        c.retain(src);
                        c.retain(dst);
                    }
                    136 => {
                        let image = self.object(a[2], Kind::Image)?;
                        let shape = shape(&image)?;
                        let native_layout = self.native_layout(a[3], false)?;
                        if c.recording.borrow().pass.is_some()
                            || !is_depth_stencil(shape.format)
                            || image.deps.borrow().is_empty()
                            || a[6] == 0
                            || !matches!(
                                native_layout,
                                vk::ImageLayout::GENERAL | vk::ImageLayout::TRANSFER_DST_OPTIMAL
                            )
                        {
                            return invalid();
                        }
                        let clear = words32(m, a[4], 2)?;
                        let depth = f32::from_bits(clear[0]);
                        let clear = vk::ClearDepthStencilValue {
                            depth,
                            stencil: clear[1],
                        };
                        let wire = words64(m, a[5], bounded(a[6], 64)? * 5)?;
                        let ranges = wire
                            .chunks_exact(5)
                            .map(|r| {if aspect_usage(&image,r[0] as u32)&2==0{return invalid();}shape.range(r)})
                            .collect::<Result<Vec<_>>>()?;
                        if ranges
                            .iter()
                            .any(|r| r.aspect_mask.contains(vk::ImageAspectFlags::DEPTH))
                            && !(0.0..=1.0).contains(&depth)
                        {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_clear_depth_stencil_image(
                                raw,
                                vk::Image::from_raw(image.raw),
                                native_layout,
                                &clear,
                                &ranges,
                            );
                        }
                        c.retain(image);
                    }
                    134 | 215 => {
                        let src = self.object(a[2], Kind::Image)?;
                        let dst = self.object(a[4], Kind::Image)?;
                        let src_shape = shape(&src)?;
                        let dst_shape = shape(&dst)?;
                        let src_layout = self.native_layout(a[3], false)?;
                        let dst_layout = self.native_layout(a[5], false)?;
                        if c.recording.borrow().pass.is_some()
                            || a[7] == 0
                            || [&src, &dst].iter().any(|i| {
                                i.deps.borrow().is_empty()
                                    && i.swapchain.borrow().is_none()
                                    && i.wayland_pool.borrow().is_none()
                            })
                            || !matches!(
                                src_layout,
                                vk::ImageLayout::GENERAL | vk::ImageLayout::TRANSFER_SRC_OPTIMAL
                            )
                            || !matches!(
                                dst_layout,
                                vk::ImageLayout::GENERAL | vk::ImageLayout::TRANSFER_DST_OPTIMAL
                            )
                        {
                            return invalid();
                        }
                        if op == 215 {
                            if src_shape.samples == vk::SampleCountFlags::TYPE_1 || dst_shape.samples != vk::SampleCountFlags::TYPE_1
                                || src_shape.format != dst_shape.format || is_depth_stencil(src_shape.format)
                            { return invalid(); }
                        } else if src_shape.samples != dst_shape.samples { return invalid(); }
                        let wire = words64(m, a[6], bounded(a[7], 64)? * 17)?;
                        let regions = wire
                            .chunks_exact(17)
                            .map(|r| {if aspect_usage(&src,r[0] as u32)&1==0 || aspect_usage(&dst,r[7] as u32)&2==0{return invalid();}checked_image_copy(r, src_shape, dst_shape)})
                            .collect::<Result<Vec<_>>>()?;
                        if src.raw == dst.raw
                            && regions.iter().any(|a| {
                                regions.iter().any(|b| {
                                    subresources_overlap(a.src_subresource, b.dst_subresource)
                                        && (src_layout != dst_layout || copy_overlap(a, b))
                                })
                            })
                        {
                            return invalid();
                        }

                        unsafe {
                            if op == 215 {
                                let regions: Vec<_> = regions.iter().map(|r| vk::ImageResolve::default()
                                    .src_subresource(r.src_subresource).src_offset(r.src_offset)
                                    .dst_subresource(r.dst_subresource).dst_offset(r.dst_offset).extent(r.extent)).collect();
                                d.cmd_resolve_image(raw, vk::Image::from_raw(src.raw), src_layout,
                                    vk::Image::from_raw(dst.raw), dst_layout, &regions);
                            } else { d.cmd_copy_image(
                                raw,
                                vk::Image::from_raw(src.raw),
                                src_layout,
                                vk::Image::from_raw(dst.raw),
                                dst_layout,
                                &regions,
                            ); }
                        }
                        // Old swapchain pools and regular image memory survive replacement,
                        // command-buffer reset and guest handle destruction until submission completion.
                        c.retain(src);
                        c.retain(dst);
                    }
                    114 => {
                        let image = self.object(a[2], Kind::Image)?;
                        let shape = shape(&image)?;
                        if c.recording.borrow().pass.is_some()
                            || is_depth_stencil(shape.format)
                            || compressed_block(shape.format.as_raw() as u64).is_some()
                            || image.flags & vk::ImageUsageFlags::TRANSFER_DST.as_raw() == 0
                            || (image.deps.borrow().is_empty()
                                && image.swapchain.borrow().is_none()
                                && image.wayland_pool.borrow().is_none())
                            || a[6] == 0
                        {
                            return invalid();
                        }
                        let native_layout = self.native_layout(a[3], false)?;
                        if !matches!(
                            native_layout,
                            vk::ImageLayout::GENERAL | vk::ImageLayout::TRANSFER_DST_OPTIMAL
                        ) {
                            return invalid();
                        }
                        let color = m.read_array::<16>(a[4])?;
                        let color = vk::ClearColorValue {
                            uint32: std::array::from_fn(|i| {
                                u32::from_le_bytes(color[i * 4..i * 4 + 4].try_into().unwrap())
                            }),
                        };
                        let wire = words64(m, a[5], bounded(a[6], 64)? * 5)?;
                        let mut ranges = Vec::new();
                        for range in wire.chunks_exact(5) {
                            ranges.push(shape.range(range)?);
                        }
                        unsafe {
                            d.cmd_clear_color_image(
                                raw,
                                vk::Image::from_raw(image.raw),
                                native_layout,
                                &color,
                                &ranges,
                            );
                        }
                        c.retain(image);
                    }
                    71 | 123 => {
                        if op == 123 && !device.renderpass2 {
                            return unsupported();
                        }
                        if c.recording.borrow().pass.is_some() {
                            return invalid();
                        }
                        let pass = self.object(a[2], Kind::RenderPass)?;
                        let fb = self.object(a[3], Kind::Framebuffer)?;
                        let s = shape(&fb)?;
                        if !compatible_pass(&fb.deps.borrow()[0], &pass)
                            || a[6] == 0
                            || a[7] == 0
                            || a[4].checked_add(a[6]).is_none_or(|x| x > s.width as u64)
                            || a[5].checked_add(a[7]).is_none_or(|y| y > s.height as u64)
                            || a[9] > pass.pass.get().unwrap().attachment_count() as u64
                            || a[9] < pass.pass.get().unwrap().clear_count as u64
                        {
                            return invalid();
                        }
                        let mut clears = Vec::new();
                        for index in 0..a[9] {
                            let words = words32(m, a[8] + index * 16, 4)?;
                            if !is_depth_stencil(pass.pass.get().unwrap().attachment_format(index as usize)) {
                                clears.push(vk::ClearValue {
                                    color: vk::ClearColorValue {
                                        float32: std::array::from_fn(|i| f32::from_bits(words[i])),
                                    },
                                });
                            } else {
                                let depth = f32::from_bits(words[0]);
                                if format_aspects(pass.pass.get().unwrap().attachment_format(index as usize)).contains(vk::ImageAspectFlags::DEPTH) && !(0.0..=1.0).contains(&depth)
                                {
                                    return invalid();
                                }
                                clears.push(vk::ClearValue {
                                    depth_stencil: vk::ClearDepthStencilValue {
                                        depth,
                                        stencil: words[1],
                                    },
                                });
                            }
                        }
                        let views: Vec<_> = descriptors::words(m,a[10],a[11],1)?
                            .into_iter()
                            .map(|id| self.object(id, Kind::ImageView))
                            .collect::<Result<_>>()?;
                        let specs = fb.attachment_specs.borrow();
                        if fb.flags == 1 {
                            if views.len() != specs.len() {
                                return invalid();
                            }
                            let p = pass.pass.get().unwrap();
                            for (i, (v, spec)) in views.iter().zip(specs.iter()).enumerate() {
                                let shape = shape(v)?;
                                let image = &v.deps.borrow()[0];
                                let wanted = p.attachment_format(i);
                                if !shape.attachment()
                                    || shape.format != wanted
                                    || shape.samples != p.sample_counts[i]
                                    || !spec.formats.contains(&shape.format)
                                    || image.image_flags.get() != spec.flags.as_raw()
                                    || image.flags != spec.usage.as_raw()
                                    || shape.width < spec.width
                                    || shape.height < spec.height
                                    || shape.layers < spec.layers
                                {
                                    return invalid();
                                }
                            }
                        } else if !views.is_empty() {
                            return invalid();
                        }
                        drop(specs);
                        let attachments: Vec<_> = views
                            .iter()
                            .map(|v| vk::ImageView::from_raw(v.raw))
                            .collect();
                        let mut attachment_info =
                            vk::RenderPassAttachmentBeginInfo::default().attachments(&attachments);
                        let mut info = vk::RenderPassBeginInfo::default()
                            .render_pass(vk::RenderPass::from_raw(pass.raw))
                            .framebuffer(vk::Framebuffer::from_raw(fb.raw))
                            .render_area(vk::Rect2D {
                                offset: vk::Offset2D {
                                    x: a[4] as i32,
                                    y: a[5] as i32,
                                },
                                extent: vk::Extent2D {
                                    width: a[6] as u32,
                                    height: a[7] as u32,
                                },
                            })
                            .clear_values(&clears);
                        if fb.flags == 1 {
                            info = info.push_next(&mut attachment_info);
                        }
                        unsafe {
                            if op == 123 {
                                let api = ash::khr::create_renderpass2::Device::new(
                                    &device.instance.native,
                                    d,
                                );
                                api.cmd_begin_render_pass2(
                                    raw,
                                    &info,
                                    &vk::SubpassBeginInfo::default()
                                        .contents(vk::SubpassContents::from_raw(a[12] as i32)),
                                );
                            } else {
                                d.cmd_begin_render_pass(raw, &info, vk::SubpassContents::from_raw(a[12] as i32));
                            }
                        }
                        for view in views {
                            c.retain(view);
                        }
                        c.recording.borrow_mut().subpass=0;
                        c.recording.borrow_mut().pass2 = op == 123;
                        c.recording.borrow_mut().render_area = Some(info.render_area);
                        c.recording.borrow_mut().layers = s.layers;
                        c.recording.borrow_mut().pass = Some(pass);
                        c.retain(fb);
                    }
                    72 | 124 => {
                        if op == 124 && !device.renderpass2 {
                            return unsupported();
                        }
                        if c.flags!=0 || c.recording.borrow().pass.is_none()
                            || c.recording.borrow().subpass+1!=c.recording.borrow().pass.as_ref().unwrap().pass.get().unwrap().subpasses.len()
                            || c.recording.borrow().feedback_active
                            || c.recording
                                .borrow()
                                .queries
                                .keys()
                                .any(|&(ty, _)| ty == vk::QueryType::OCCLUSION.as_raw())
                        {
                            return invalid();
                        }
                        unsafe {
                            if op == 124 {
                                let api = ash::khr::create_renderpass2::Device::new(
                                    &device.instance.native,
                                    d,
                                );
                                api.cmd_end_render_pass2(raw, &vk::SubpassEndInfo::default());
                            } else {
                                d.cmd_end_render_pass(raw);
                            }
                        }
                        c.recording.borrow_mut().pass = None;
                        c.recording.borrow_mut().render_area = None;
                    }
                    73 | 97 => {
                        let r = c.recording.borrow();
                        let pass = r
                            .pass
                            .as_ref()
                            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                        let p = r
                            .pipeline
                            .as_ref()
                            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                        if p.flags != vk::PipelineBindPoint::GRAPHICS.as_raw() as u32
                            || (!r.viewport && p.static_states.get() & 1 == 0)
                            || (!r.scissor && p.static_states.get() & 2 == 0)
                            || p.size as usize!=r.subpass
                            || !compatible_pass(&p.deps.borrow()[1], pass)
                            || a[2..5].iter().any(|&x| x > u32::MAX as u64)
                            || (op == 73 && a[5] > u32::MAX as u64)
                            || (op == 97
                                && ((a[5] as i64) != (a[5] as i32 as i64)
                                    || a[6] > u32::MAX as u64))
                        {
                            return invalid();
                        }
                        let active = a[2] != 0 && a[3] != 0;
                        let first_instance = if op == 97 { a[6] } else { a[5] };
                        instance_base(&p.vertex_inputs.borrow(), first_instance)?;
                        for input in p.vertex_inputs.borrow().iter().filter(|x| x.extent != 0) {
                            let (buffer, offset) = r
                                .vertices
                                .get(&input.binding)
                                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                            // GPU-resident index values stay on the GPU. Check the index
                            // range below; as on Vulkan, indexed vertex values are the
                            // application's responsibility, not a CPU readback/scan.
                            let last = if !active || op == 97 && !input.instance {
                                0
                            } else if input.instance {
                                last_instance(first_instance, a[3], input.divisor)?
                            } else {
                                a[4].checked_add(a[2] - 1)
                                    .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?
                            };
                            if active
                                && last
                                    .checked_mul(input.stride as u64)
                                    .and_then(|n| n.checked_add(*offset))
                                    .and_then(|n| n.checked_add(input.extent as u64))
                                    .is_none_or(|n| n > buffer.size)
                            {
                                return invalid();
                            }
                        }
                        if op == 97 {
                            let (buffer, offset, size) = r
                                .index
                                .as_ref()
                                .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                            if a[4]
                                .checked_add(a[2])
                                .and_then(|n| n.checked_mul(*size as u64))
                                .and_then(|n| n.checked_add(*offset))
                                .is_none_or(|n| n > buffer.size)
                            {
                                return invalid();
                            }
                            unsafe {
                                d.cmd_draw_indexed(
                                    raw,
                                    a[2] as u32,
                                    a[3] as u32,
                                    a[4] as u32,
                                    a[5] as i32,
                                    a[6] as u32,
                                );
                            }
                        } else {
                            unsafe {
                                d.cmd_draw(raw, a[2] as u32, a[3] as u32, a[4] as u32, a[5] as u32);
                            }
                        }
                    }
                    74 | 94 => {
                        if c.recording.borrow().pass.is_some() {
                            return invalid();
                        }
                        let image = self.object(a[2], Kind::Image)?;
                        let buffer = self.object(a[4], Kind::Buffer)?;
                        let s = shape(&image)?;
                        if image.deps.borrow().is_empty()
                            && image.swapchain.borrow().is_none()
                            && image.wayland_pool.borrow().is_none()
                            || buffer.deps.borrow().is_empty()
                            || buffer.flags
                                & (if op == 94 {
                                    vk::BufferUsageFlags::TRANSFER_SRC
                                } else {
                                    vk::BufferUsageFlags::TRANSFER_DST
                                })
                                .as_raw()
                                == 0
                            || a[3] != 1 && a[3] != if op == 94 { 7 } else { 6 }
                            || a[6] == 0
                        {
                            return invalid();
                        }
                        let wire = words64(m, a[5], bounded(a[6], 64)? * 13)?;
                        let mut regions = Vec::new();
                        for x in wire.chunks_exact(13) {
                            if aspect_usage(&image,x[3] as u32)&(if op==94{2}else{1})==0{return invalid();}
                            checked_copy(x, s, buffer.size)?;
                            regions.push(
                                vk::BufferImageCopy::default()
                                    .buffer_offset(x[0])
                                    .buffer_row_length(x[1] as u32)
                                    .buffer_image_height(x[2] as u32)
                                    .image_subresource(
                                        vk::ImageSubresourceLayers::default()
                                            .aspect_mask(vk::ImageAspectFlags::from_raw(
                                                x[3] as u32,
                                            ))
                                            .mip_level(x[4] as u32)
                                            .base_array_layer(x[5] as u32)
                                            .layer_count(x[6] as u32),
                                    )
                                    .image_offset(vk::Offset3D {
                                        x: x[7] as i32,
                                        y: x[8] as i32,
                                        z: x[9] as i32,
                                    })
                                    .image_extent(vk::Extent3D {
                                        width: x[10] as u32,
                                        height: x[11] as u32,
                                        depth: x[12] as u32,
                                    }),
                            );
                        }
                        unsafe {
                            if op == 94 {
                                d.cmd_copy_buffer_to_image(
                                    raw,
                                    vk::Buffer::from_raw(buffer.raw),
                                    vk::Image::from_raw(image.raw),
                                    self.native_layout(a[3], false)?,
                                    &regions,
                                );
                            } else {
                                d.cmd_copy_image_to_buffer(
                                    raw,
                                    vk::Image::from_raw(image.raw),
                                    self.native_layout(a[3], false)?,
                                    vk::Buffer::from_raw(buffer.raw),
                                    &regions,
                                );
                            }
                        }
                        c.retain(image);
                        c.retain(buffer);
                    }
                    95 => {
                        if a[3] == 0 || a[2].checked_add(a[3]).is_none_or(|n| n > 16) {
                            return unsupported();
                        }
                        let ids = words64(m, a[4], bounded(a[3], 16)?)?;
                        let offsets = words64(m, a[5], ids.len())?;
                        let mut buffers = Vec::new();
                        let mut objects = Vec::new();
                        for (&id, &offset) in ids.iter().zip(&offsets) {
                            let b = self.object(id, Kind::Buffer)?;
                            if b.flags & vk::BufferUsageFlags::VERTEX_BUFFER.as_raw() == 0
                                || b.deps.borrow().is_empty()
                                || offset >= b.size
                            {
                                return invalid();
                            }
                            buffers.push(vk::Buffer::from_raw(b.raw));
                            objects.push(b);
                        }
                        unsafe {
                            d.cmd_bind_vertex_buffers(raw, a[2] as u32, &buffers, &offsets);
                        }
                        for (i, (b, offset)) in objects.into_iter().zip(offsets).enumerate() {
                            c.recording
                                .borrow_mut()
                                .vertices
                                .insert(a[2] as u32 + i as u32, (b.clone(), offset));
                            c.retain(b);
                        }
                    }
                    96 => {
                        let b = self.object(a[2], Kind::Buffer)?;
                        let size = match a[4] {
                            0 => 2,
                            1 => 4,
                            _ => return unsupported(),
                        };
                        if b.flags & vk::BufferUsageFlags::INDEX_BUFFER.as_raw() == 0
                            || b.deps.borrow().is_empty()
                            || a[3] >= b.size
                            || !a[3].is_multiple_of(size as u64)
                        {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_bind_index_buffer(
                                raw,
                                vk::Buffer::from_raw(b.raw),
                                a[3],
                                vk::IndexType::from_raw(a[4] as i32),
                            );
                        }
                        c.recording.borrow_mut().index = Some((b.clone(), a[3], size));
                        c.retain(b);
                    }
                    75 => {
                        let v = words32(m, a[2], 6)?;
                        let v: Vec<_> = v.into_iter().map(f32::from_bits).collect();
                        if !valid_viewport(
                            &v,
                            device.maintenance1,
                            device.viewport_dimensions,
                            device.viewport_bounds,
                        ) {
                            if std::env::var_os("TRAMES_VULKAN_TRACE").is_some() {
                                eprintln!("trames-vulkan invalid viewport {v:?}");
                            }
                            return invalid();
                        }
                        let viewport = [vk::Viewport {
                            x: v[0],
                            y: v[1],
                            width: v[2],
                            height: v[3],
                            min_depth: v[4],
                            max_depth: v[5],
                        }];
                        unsafe {
                            d.cmd_set_viewport(raw, 0, &viewport);
                        }
                        c.recording.borrow_mut().viewport = true;
                    }
                    76 => {
                        if a[4] == 0
                            || a[5] == 0
                            || a[2].checked_add(a[4]).is_none_or(|x| x > DIMENSION as u64)
                            || a[3].checked_add(a[5]).is_none_or(|y| y > DIMENSION as u64)
                        {
                            return invalid();
                        }
                        let rect = [vk::Rect2D {
                            offset: vk::Offset2D {
                                x: a[2] as i32,
                                y: a[3] as i32,
                            },
                            extent: vk::Extent2D {
                                width: a[4] as u32,
                                height: a[5] as u32,
                            },
                        }];
                        unsafe {
                            d.cmd_set_scissor(raw, 0, &rect);
                        }
                        c.recording.borrow_mut().scissor = true;
                    }
                    _ => unreachable!(),
                }
            }
            _ => return unsupported(),
        }
        Ok(())
    }
}
fn indirect_span(size: u64, offset: u64, count: u64, stride: u64, command_size: u64) -> Result<()> {
    if !offset.is_multiple_of(4) || offset > size
        || count > 1 && (!stride.is_multiple_of(4) || stride < command_size || stride > u32::MAX as u64)
    { return invalid(); }
    let bytes = if count == 0 { Some(0) } else if count == 1 { Some(command_size) }
        else { (count - 1).checked_mul(stride).and_then(|n| n.checked_add(command_size)) };
    if bytes.and_then(|n| offset.checked_add(n)).is_none_or(|end| end > size) { return invalid(); }
    Ok(())
}
fn valid_viewport(v: &[f32], maintenance1: bool, dimensions: [u32; 2], bounds: [f32; 2]) -> bool {
    v.iter().all(|v| v.is_finite())
        && v[0] >= bounds[0]
        && v[1] >= bounds[0]
        && v[2] > 0.0
        && (v[3] > 0.0 || maintenance1)
        && v[2] <= dimensions[0] as f32
        && v[3].abs() <= dimensions[1] as f32
        && v[0] + v[2] <= bounds[1]
        && v[1] <= bounds[1]
        && (bounds[0]..=bounds[1]).contains(&(v[1] + v[3]))
        && (0.0..=1.0).contains(&v[4])
        && (0.0..=1.0).contains(&v[5])
}

fn image_type(raw: u64) -> Result<vk::ImageType> {
    match raw {
        0..=2 => Ok(vk::ImageType::from_raw(raw as i32)),
        _ => Err(vk::Result::ERROR_FORMAT_NOT_SUPPORTED.into()),
    }
}
fn sample_count(value: u64) -> Result<vk::SampleCountFlags> {
    if value == 0 || value > 64 || !value.is_power_of_two() { return invalid(); }
    Ok(vk::SampleCountFlags::from_raw(value as u32))
}
fn validate_shape(s: ImageShape, flags: u64) -> Result<()> {
    let ext = [s.width, s.height, s.depth];
    if ext.iter().any(|&n| n == 0 || n > DIMENSION)
        || s.layers == 0
        || s.layers > LAYERS
        || s.mips == 0
        || s.samples != vk::SampleCountFlags::TYPE_1 && (s.ty != vk::ImageType::TYPE_2D || s.mips != 1 || flags & 16 != 0)
        || s.mips > ext.into_iter().max().unwrap().ilog2() + 1
        || s.ty == vk::ImageType::TYPE_1D && (s.height != 1 || s.depth != 1)
        || s.ty == vk::ImageType::TYPE_2D && s.depth != 1
        || s.ty == vk::ImageType::TYPE_3D && s.layers != 1
        || flags & !0x138 != 0
        || flags & 32 != 0 && s.ty != vk::ImageType::TYPE_3D
        || flags & 16 != 0
            && (s.ty != vk::ImageType::TYPE_2D || s.width != s.height || s.layers < 6)
    {
        return invalid();
    }
    Ok(())
}
fn validate_view(
    s: ImageShape,
    flags: u32,
    ty: vk::ImageViewType,
    r: vk::ImageSubresourceRange,
) -> Result<()> {
    let valid = match ty {
        vk::ImageViewType::TYPE_1D => s.ty == vk::ImageType::TYPE_1D && r.layer_count == 1,
        vk::ImageViewType::TYPE_1D_ARRAY => s.ty == vk::ImageType::TYPE_1D,
        vk::ImageViewType::TYPE_2D => {
            (s.ty == vk::ImageType::TYPE_2D
                || s.ty == vk::ImageType::TYPE_3D && flags & 32 != 0 && r.level_count == 1)
                && r.layer_count == 1
        }
        vk::ImageViewType::TYPE_2D_ARRAY => {
            s.ty == vk::ImageType::TYPE_2D
                || s.ty == vk::ImageType::TYPE_3D && flags & 32 != 0 && r.level_count == 1
        }
        vk::ImageViewType::TYPE_3D => s.ty == vk::ImageType::TYPE_3D,
        vk::ImageViewType::CUBE => flags & 16 != 0 && r.layer_count == 6,
        // Array cubes additionally require the device's imageCubeArray feature;
        // that feature is checked at the call site, not invented here.
        vk::ImageViewType::CUBE_ARRAY => flags & 16 != 0 && r.layer_count.is_multiple_of(6),
        _ => false,
    };
    if !valid {
        return invalid();
    }
    Ok(())
}
fn validate_divisor(instance: bool, divisor: u64, enabled: Option<zink::Divisor>) -> Result<()> {
    if divisor != 1
        && (!instance
            || enabled.is_none_or(|p| divisor > p.maximum as u64 || divisor == 0 && !p.zero))
    {
        return unsupported();
    }
    Ok(())
}
// EXT exposes no supportsNonZeroFirstInstance property. Preserve the selected
// profile's restriction for all bindings, including those unused by this shader.
pub(super) fn instance_base(inputs: &[VertexBinding], first: u64) -> Result<()> {
    if first != 0 && inputs.iter().any(|v| v.instance && v.divisor != 1) {
        return unsupported();
    }
    Ok(())
}
fn last_instance(first: u64, count: u64, divisor: u32) -> Result<u64> {
    if count == 0 || divisor == 0 {
        return Ok(0);
    }
    let last = if divisor == 1 {
        count - 1
    } else {
        (count - 1) / divisor as u64
    };
    first
        .checked_add(last)
        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))
}
fn stencil_state(wire: &[u64]) -> Result<vk::StencilOpState> {
    if wire.len() != 7
        || wire[..4].iter().any(|&v| v > 7)
        || wire[4..].iter().any(|&v| v > u32::MAX as u64)
    {
        return invalid();
    }
    Ok(vk::StencilOpState::default()
        .fail_op(vk::StencilOp::from_raw(wire[0] as i32))
        .pass_op(vk::StencilOp::from_raw(wire[1] as i32))
        .depth_fail_op(vk::StencilOp::from_raw(wire[2] as i32))
        .compare_op(vk::CompareOp::from_raw(wire[3] as i32))
        .compare_mask(wire[4] as u32)
        .write_mask(wire[5] as u32)
        .reference(wire[6] as u32))
}
fn checked_region(
    s: ImageShape,
    sub: &[u64],
    offset: &[u64],
    extent: &[u64],
) -> Result<vk::ImageSubresourceLayers> {
    let layers = s.layers(sub)?;
    let mut bounds = s.extent(sub[1])?;
    if let Some((_,x,y))=ycbcr::plane(s.format.as_raw() as u64,sub[0]){bounds[0]=bounds[0].div_ceil(x);bounds[1]=bounds[1].div_ceil(y);}
    for i in 0..3 {
        if extent[i] == 0
            || offset[i]
                .checked_add(extent[i])
                .is_none_or(|n| n > bounds[i] as u64)
        {
            return invalid();
        }
    }
    Ok(layers)
}
fn checked_blocks(image: ImageShape, mip: u64, offset: &[u64], extent: &[u64]) -> Result<()> {
    let Some((width, height, _)) = compressed_block(image.format.as_raw() as u64).or_else(||ycbcr::packed(image.format.as_raw() as u64)) else { return Ok(()) };
    let edge = image.extent(mip)?;
    for (axis, block) in [(0, width), (1, height)] {
        if !offset[axis].is_multiple_of(block)
            || !extent[axis].is_multiple_of(block) && offset[axis] + extent[axis] != edge[axis] as u64
        { return invalid(); }
    }
    Ok(())
}
fn checked_copy(x: &[u64], image: ImageShape, buffer_size: u64) -> Result<()> {
    if image.samples != vk::SampleCountFlags::TYPE_1 { return invalid(); }
    // Packed depth/stencil is transferred one aspect at a time: D32S8 uses
    // four bytes for depth and one for stencil, never eight bytes per aspect.
    let bytes = aspect_bytes(image.format, x[3])?;
    let _ = checked_region(image, &x[3..7], &x[7..10], &x[10..13])?;
    if x[1] != 0 && x[1] < x[10]
        || x[2] != 0 && x[2] < x[11]
        || !x[0].is_multiple_of(4)
        || !x[0].is_multiple_of(bytes)
        || x[1] > u32::MAX as u64
        || x[2] > u32::MAX as u64
    {
        return invalid();
    }
    let (bw, bh, _) = block_layout(ycbcr::transfer_format(image.format,x[3])?.as_raw() as u64).ok_or(Failure::Vk(vk::Result::ERROR_FORMAT_NOT_SUPPORTED))?;
    checked_blocks(image, x[4], &x[7..10], &x[10..13])?;
    if x[1] != 0 && !x[1].is_multiple_of(bw) || x[2] != 0 && !x[2].is_multiple_of(bh) { return invalid(); }
    let row = (if x[1] == 0 { x[10] } else { x[1] }).div_ceil(bw);
    let height = (if x[2] == 0 { x[11] } else { x[2] }).div_ceil(bh);
    // Array layers and volume slices both advance by bufferImageHeight rows.
    // The last row does not require its padding to exist in the buffer.
    let slices = x[6]
        .checked_mul(x[12])
        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
    if (slices - 1)
        .checked_mul(height)
        .and_then(|n| n.checked_add(x[11].div_ceil(bh) - 1))
        .and_then(|n| n.checked_mul(row))
        .and_then(|n| n.checked_add(x[10].div_ceil(bw)))
        .and_then(|n| n.checked_mul(bytes))
        .and_then(|n| n.checked_add(x[0]))
        .is_none_or(|n| n > buffer_size)
    {
        return invalid();
    }
    Ok(())
}
fn checked_image_copy(x: &[u64], src: ImageShape, dst: ImageShape) -> Result<vk::ImageCopy> {
    let depth = is_depth_stencil(src.format);
    if depth != is_depth_stencil(dst.format)
        || depth && src.format != dst.format
        || block_layout(ycbcr::transfer_format(src.format,x[0])?.as_raw() as u64) != block_layout(ycbcr::transfer_format(dst.format,x[7])?.as_raw() as u64)
        || (src.ty == vk::ImageType::TYPE_3D) != (dst.ty == vk::ImageType::TYPE_3D)
    {
        return unsupported();
    }
    let src_sub = checked_region(src, &x[..4], &x[4..7], &x[14..17])?;
    let dst_sub = checked_region(dst, &x[7..11], &x[11..14], &x[14..17])?;
    checked_blocks(src, x[1], &x[4..7], &x[14..17])?;
    checked_blocks(dst, x[8], &x[11..14], &x[14..17])?;
    if src_sub.layer_count != dst_sub.layer_count || depth && src_sub.aspect_mask != dst_sub.aspect_mask {
        return invalid();
    }
    Ok(vk::ImageCopy::default()
        .src_subresource(src_sub)
        .dst_subresource(dst_sub)
        .src_offset(vk::Offset3D {
            x: x[4] as i32,
            y: x[5] as i32,
            z: x[6] as i32,
        })
        .dst_offset(vk::Offset3D {
            x: x[11] as i32,
            y: x[12] as i32,
            z: x[13] as i32,
        })
        .extent(vk::Extent3D {
            width: x[14] as u32,
            height: x[15] as u32,
            depth: x[16] as u32,
        }))
}
fn subresources_overlap(a: vk::ImageSubresourceLayers, b: vk::ImageSubresourceLayers) -> bool {
    a.mip_level == b.mip_level
        && a.aspect_mask.intersects(b.aspect_mask)
        && a.base_array_layer < b.base_array_layer + b.layer_count
        && b.base_array_layer < a.base_array_layer + a.layer_count
}
fn copy_overlap(a: &vk::ImageCopy, b: &vk::ImageCopy) -> bool {
    if !subresources_overlap(a.src_subresource, b.dst_subresource) {
        return false;
    }
    let src = [a.src_offset.x, a.src_offset.y, a.src_offset.z];
    let dst = [b.dst_offset.x, b.dst_offset.y, b.dst_offset.z];
    let se = [a.extent.width, a.extent.height, a.extent.depth];
    let de = [b.extent.width, b.extent.height, b.extent.depth];
    (0..3)
        .all(|i| (src[i] as u32) < dst[i] as u32 + de[i] && (dst[i] as u32) < src[i] as u32 + se[i])
}
fn numeric_class(f: vk::Format) -> u8 {
    match f.as_raw() {
        13 | 20 | 27 | 34 | 41 | 48 | 55 | 62 | 68 | 74 | 81 | 88 | 95 | 98 | 101 | 104 | 107 => 1,
        14 | 21 | 28 | 35 | 42 | 49 | 56 | 63 | 69 | 75 | 82 | 89 | 96 | 99 | 102 | 105 | 108 => 2,
        _ => 0,
    }
}
fn checked_blit(x: &[u64], src: ImageShape, dst: ImageShape) -> Result<vk::ImageBlit> {
    if src.samples != vk::SampleCountFlags::TYPE_1 || dst.samples != vk::SampleCountFlags::TYPE_1 { return invalid(); }
    if is_depth_stencil(src.format) != is_depth_stencil(dst.format)
        || is_depth_stencil(src.format) && src.format != dst.format
        || numeric_class(src.format) != numeric_class(dst.format)
        || src.ty != dst.ty
    {
        return unsupported();
    }
    let mut subs = Vec::new();
    let mut offsets = Vec::new();
    for (at, shape) in [(0, src), (10, dst)] {
        subs.push(shape.layers(&x[at..at + 4])?);
        let extent = shape.extent(x[at + 1])?;
        let mut o = [vk::Offset3D::default(); 2];
        for axis in 0..3 {
            let a = x[at + 4 + axis];
            let b = x[at + 7 + axis];
            if a == b
                || a > extent[axis] as u64
                || b > extent[axis] as u64
                || axis == 1 && shape.ty == vk::ImageType::TYPE_1D && (a != 0 || b != 1)
                || axis == 2 && shape.ty != vk::ImageType::TYPE_3D && (a != 0 || b != 1)
            {
                return invalid();
            }
        }
        for i in 0..2 {
            o[i] = vk::Offset3D {
                x: x[at + 4 + i * 3] as i32,
                y: x[at + 5 + i * 3] as i32,
                z: x[at + 6 + i * 3] as i32,
            };
        }
        offsets.push(o);
    }
    if subs[0].layer_count != subs[1].layer_count || subs[0].aspect_mask != subs[1].aspect_mask {
        return invalid();
    }
    Ok(vk::ImageBlit::default()
        .src_subresource(subs[0])
        .dst_subresource(subs[1])
        .src_offsets(offsets[0])
        .dst_offsets(offsets[1]))
}
fn blit_overlap(a: &vk::ImageBlit, b: &vk::ImageBlit) -> bool {
    if !subresources_overlap(a.src_subresource, b.dst_subresource) {
        return false;
    }
    let src = a.src_offsets.map(|p| [p.x, p.y, p.z]);
    let dst = b.dst_offsets.map(|p| [p.x, p.y, p.z]);
    (0..3).all(|i| {
        src[0][i].min(src[1][i]) < dst[0][i].max(dst[1][i])
            && dst[0][i].min(dst[1][i]) < src[0][i].max(src[1][i])
    })
}

fn clear_attachment(pass: &SubpassInfo, wire: &[u64]) -> Result<vk::ClearAttachment> {
    if !matches!(wire[0], 1 | 2 | 4 | 6) {
        return invalid();
    }
    let aspect = vk::ImageAspectFlags::from_raw(wire[0] as u32);
    if aspect == vk::ImageAspectFlags::COLOR {
        // An UNUSED subpass color slot is ignored by Vulkan, not remapped to
        // the compact framebuffer attachment index.
        if wire[1] >= pass.color_count as u64 {
            return invalid();
        }
    } else if pass
        .depth
        .is_none_or(|f| !format_aspects(f).contains(aspect))
    {
        return invalid();
    }
    let mut bits = [0; 4];
    for (out, value) in bits.iter_mut().zip(&wire[2..6]) {
        *out = u32::try_from(*value).map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
    }
    if aspect.contains(vk::ImageAspectFlags::DEPTH)
        && !(0.0..=1.0).contains(&f32::from_bits(bits[0]))
    {
        return invalid();
    }
    Ok(vk::ClearAttachment::default()
        .aspect_mask(aspect)
        .color_attachment(wire[1] as u32)
        .clear_value(vk::ClearValue {
            color: vk::ClearColorValue { uint32: bits },
        }))
}
fn clear_rectangle(area: vk::Rect2D, wire: &[u64], layers:u32) -> Result<vk::ClearRect> {
    if wire[0] < area.offset.x as u64
        || wire[1] < area.offset.y as u64
        || wire[5]==0 || wire[4].checked_add(wire[5]).is_none_or(|end|end>layers as u64)
        || wire[0]
            .checked_add(wire[2])
            .is_none_or(|v| v > area.offset.x as u64 + area.extent.width as u64)
        || wire[1]
            .checked_add(wire[3])
            .is_none_or(|v| v > area.offset.y as u64 + area.extent.height as u64)
    {
        if std::env::var_os("TRAMES_VULKAN_TRACE").is_some() {
            eprintln!("trames-vulkan clear rectangle area={area:?} rect={wire:?}");
        }
        return invalid();
    }
    Ok(vk::ClearRect::default()
        .rect(vk::Rect2D {
            offset: vk::Offset2D {
                x: wire[0] as i32,
                y: wire[1] as i32,
            },
            extent: vk::Extent2D {
                width: wire[2] as u32,
                height: wire[3] as u32,
            },
        })
        .base_array_layer(wire[4] as u32)
        .layer_count(wire[5] as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subsampled_plane_transfers_bound_the_real_compatible_extent() {
        let s=ImageShape::d2(7,5,vk::Format::G8_B8R8_2PLANE_420_UNORM);
        let mut copy=[0,0,0,32,0,0,1,0,0,0,4,3,1];
        assert!(checked_copy(&copy,s,24).is_ok());
        assert!(checked_copy(&copy,s,23).is_err());
        copy[10]=5;assert!(checked_copy(&copy,s,64).is_err());
        copy[10]=4;copy[3]=64;assert!(checked_copy(&copy,s,64).is_err());
        copy[3]=1;assert!(checked_copy(&copy,s,64).is_err());
        copy[3]=16;copy[10]=7;copy[11]=5;assert!(checked_copy(&copy,s,35).is_ok());
    }
    #[test]
    fn layered_clear_preserves_the_requested_slice_range() {
        let area=vk::Rect2D{offset:vk::Offset2D::default(),extent:vk::Extent2D{width:16,height:8}};
        let clear=clear_rectangle(area,&[0,0,16,8,2,3],5).unwrap();
        assert_eq!((clear.base_array_layer,clear.layer_count),(2,3));
        assert!(clear_rectangle(area,&[0,0,16,8,2,4],5).is_err());
    }
    #[test]
    fn attachment_references_preserve_general_and_read_only_layouts() {
        for depth in [false, true] {
            assert_eq!(
                attachment_reference_layout(1, depth).unwrap(),
                vk::ImageLayout::GENERAL
            );
            assert_eq!(
                attachment_reference_layout(1000339000, depth).unwrap(),
                vk::ImageLayout::GENERAL
            );
            for bad in [0, 5, 6, 7, 1000001002] {
                assert!(attachment_reference_layout(bad, depth).is_err());
            }
        }
        assert_eq!(
            attachment_reference_layout(2, false).unwrap(),
            vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL
        );
        assert!(attachment_reference_layout(2, true).is_err());
        assert_eq!(
            attachment_reference_layout(4, true).unwrap(),
            vk::ImageLayout::DEPTH_STENCIL_READ_ONLY_OPTIMAL
        );
        assert!(attachment_reference_layout(4, false).is_err());
    }
    #[test]
    fn attachment_clears_preserve_subpass_slots_aspects_and_render_area() {
        let mut pass = PassInfo::new(3);
        pass.depth = Some(vk::Format::D24_UNORM_S8_UINT);
        pass.colors[0] = vk::Format::R8G8B8A8_UNORM;
        pass.colors[2] = vk::Format::R8G8B8A8_UNORM;
        assert_eq!(
            clear_attachment(&pass, &[1, 2, 7, 8, 9, 10])
                .unwrap()
                .color_attachment,
            2
        );
        assert!(clear_attachment(&pass, &[1, 1, 0, 0, 0, 0]).is_ok()); // UNUSED is ignored
        assert!(clear_attachment(&pass, &[1, 3, 0, 0, 0, 0]).is_err());
        let depth = 0.75f32.to_bits() as u64;
        for aspects in [2, 4, 6] {
            assert!(clear_attachment(&pass, &[aspects, 999, depth, 0xab, 0, 0]).is_ok());
        }
        for aspects in [0, 3, 5, 7, 8] {
            assert!(clear_attachment(&pass, &[aspects, 0, depth, 0, 0, 0]).is_err());
        }
        assert!(clear_attachment(&pass, &[2, 0, f32::NAN.to_bits() as u64, 0, 0, 0]).is_err());
        pass.depth = Some(vk::Format::D16_UNORM);
        assert!(clear_attachment(&pass, &[4, 0, 0, 0, 0, 0]).is_err());
        let area = vk::Rect2D {
            offset: vk::Offset2D { x: 8, y: 4 },
            extent: vk::Extent2D {
                width: 16,
                height: 12,
            },
        };
        assert!(clear_rectangle(area, &[8, 4, 16, 12, 0, 1],1).is_ok());
        // VkClearRect requires a nonzero layer count, not a nonzero extent.
        // Clipped GL clears can legitimately reach an empty framebuffer edge.
        for rectangle in [
            [24, 4, 0, 12, 0, 1],
            [8, 16, 16, 0, 0, 1],
            [24, 16, 0, 0, 0, 1],
        ] {
            assert!(clear_rectangle(area, &rectangle,1).is_ok());
        }
        for rectangle in [
            [7, 4, 1, 1, 0, 1],
            [8, 3, 1, 1, 0, 1],
            [8, 4, 17, 12, 0, 1],
            [8, 4, 16, 13, 0, 1],
            [25, 4, 0, 1, 0, 1],
            [8, 17, 1, 0, 0, 1],
            [8, 4, 1, 1, 0, 0],
            [8, 4, 1, 1, 1, 1],
            [8, 4, 1, 1, 0, 2],
            [u64::MAX, 4, 2, 1, 0, 1],
        ] {
            assert!(clear_rectangle(area, &rectangle,1).is_err());
        }
    }
    #[test]
    fn divisor_features_and_instance_footprints() {
        let native = Some(zink::Divisor {
            maximum: u32::MAX,
            zero: true,
        });
        assert!(validate_divisor(false, 1, None).is_ok());
        assert!(validate_divisor(true, 1, None).is_ok());
        assert!(validate_divisor(false, 2, native).is_err());
        assert!(validate_divisor(true, 2, None).is_err());
        assert!(validate_divisor(true, 0, native).is_ok());
        assert!(validate_divisor(
            true,
            0,
            Some(zink::Divisor {
                maximum: 8,
                zero: false
            })
        )
        .is_err());
        assert!(validate_divisor(
            true,
            9,
            Some(zink::Divisor {
                maximum: 8,
                zero: true
            })
        )
        .is_err());
        assert!(validate_divisor(true, 1 << 32, native).is_err());
        assert_eq!(last_instance(0, 8, 2).unwrap(), 3);
        assert_eq!(last_instance(0, 8, 3).unwrap(), 2);
        assert_eq!(last_instance(2, 4, 1).unwrap(), 5);
        assert_eq!(last_instance(0, 8, u32::MAX).unwrap(), 0);
        assert_eq!(last_instance(0, u32::MAX as u64, 0).unwrap(), 0);
        assert_eq!(last_instance(0, 0, 1).unwrap(), 0);
        assert!(last_instance(u64::MAX, 2, 1).is_err());
        let mut binding = VertexBinding {
            binding: 5,
            stride: 24,
            instance: true,
            divisor: 2,
            extent: 0,
        };
        assert!(instance_base(&[binding.clone()], 0).is_ok());
        assert!(instance_base(&[binding.clone()], 1).is_err());
        binding.divisor = 1;
        assert!(instance_base(&[binding], 7).is_ok());
    }
    #[test]
    fn blit_format_conversion_and_volume_slice_views_follow_native_rules() {
        let rgba = ImageShape::d2(4, 4, vk::Format::R8G8B8A8_UNORM);
        let wire = [1, 0, 0, 1, 0, 0, 0, 4, 4, 1, 1, 0, 0, 1, 0, 0, 0, 2, 2, 1];
        assert!(checked_blit(
            &wire,
            rgba,
            ImageShape {
                format: vk::Format::B8G8R8A8_UNORM,
                ..rgba
            }
        )
        .is_ok());
        assert!(checked_blit(
            &wire,
            rgba,
            ImageShape {
                format: vk::Format::R8G8B8A8_UINT,
                ..rgba
            }
        )
        .is_err());
        let sint = ImageShape {
            format: vk::Format::R16_SINT,
            ..rgba
        };
        assert!(checked_blit(
            &wire,
            sint,
            ImageShape {
                format: vk::Format::R32_SINT,
                ..rgba
            }
        )
        .is_ok());
        assert!(checked_blit(
            &wire,
            sint,
            ImageShape {
                format: vk::Format::R32_UINT,
                ..rgba
            }
        )
        .is_err());
        let volume = ImageShape {
            ty: vk::ImageType::TYPE_3D,
            depth: 4,
            mips: 3,
            ..rgba
        };
        assert!(validate_shape(volume, 32).is_ok());
        assert!(validate_shape(rgba, 32).is_err());
        let range = vk::ImageSubresourceRange::default()
            .aspect_mask(vk::ImageAspectFlags::COLOR)
            .base_mip_level(1)
            .level_count(1)
            .base_array_layer(1)
            .layer_count(1);
        assert!(validate_view(volume, 32, vk::ImageViewType::TYPE_2D, range).is_ok());
        assert!(validate_view(volume, 0, vk::ImageViewType::TYPE_2D, range).is_err());
        assert!(validate_view(
            volume,
            32,
            vk::ImageViewType::TYPE_2D,
            vk::ImageSubresourceRange {
                level_count: 2,
                ..range
            }
        )
        .is_err());
        let mut flipped = wire;
        flipped[6] = 1;
        flipped[9] = 0;
        assert!(checked_blit(&flipped, rgba, rgba).is_err());
    }
    #[test]
    fn subresource_ranges_cube_views_and_mip_bounds() {
        let s = ImageShape {
            mips: 4,
            layers: 12,
            ..ImageShape::d2(8, 8, vk::Format::R8G8B8A8_UNORM)
        };
        assert!(validate_shape(s, 16).is_ok());
        let r = s
            .range(&[1, 1, u32::MAX as u64, 6, u32::MAX as u64])
            .unwrap();
        assert_eq!((r.level_count, r.layer_count), (3, 6));
        assert!(validate_view(s, 16, vk::ImageViewType::CUBE, r).is_ok());
        assert!(validate_view(s, 0, vk::ImageViewType::CUBE, r).is_err());
        assert!(validate_view(s, 16, vk::ImageViewType::TYPE_2D, r).is_err());
        assert_eq!(s.extent(3).unwrap(), [1, 1, 1]);
        for bad in [
            [1, 4, 1, 0, 1],
            [1, 3, 2, 0, 1],
            [1, 0, 0, 0, 1],
            [1, 0, 1, 12, 1],
            [1, 0, 1, 10, 3],
            [2, 0, 1, 0, 1],
        ] {
            assert!(s.range(&bad).is_err());
        }
        assert!(validate_shape(ImageShape { mips: 5, ..s }, 16).is_err());
        assert!(validate_shape(ImageShape { width: 4, ..s }, 16).is_err());
        assert!(validate_shape(ImageShape { layers: 5, ..s }, 16).is_err());
        assert!(validate_shape(
            ImageShape {
                ty: vk::ImageType::TYPE_3D,
                ..s
            },
            0
        )
        .is_err());
    }
    #[test]
    fn array_and_volume_copy_footprints_include_slice_padding() {
        let array = ImageShape {
            mips: 4,
            layers: 6,
            ..ImageShape::d2(8, 8, vk::Format::R8G8B8A8_UNORM)
        };
        let volume = ImageShape {
            ty: vk::ImageType::TYPE_3D,
            depth: 8,
            layers: 1,
            ..array
        };
        let cases = [
            (array, [16, 6, 5, 1, 1, 2, 3, 1, 1, 0, 3, 2, 1]),
            (volume, [16, 6, 5, 1, 1, 0, 1, 1, 1, 1, 3, 2, 3]),
        ];
        for (s, r) in cases {
            let bytes = 16 + ((2 * 5 + 1) * 6 + 3) * 4;
            assert!(checked_copy(&r, s, bytes).is_ok());
            assert!(checked_copy(&r, s, bytes - 1).is_err());
            for (index, value) in [
                (0, u64::MAX - 3),
                (1, u64::MAX),
                (4, 4),
                (7, 2),
                (8, 3),
                (10, 0),
            ] {
                let mut bad = r;
                bad[index] = value;
                assert!(checked_copy(&bad, s, u64::MAX).is_err());
            }
        }
        let mut r = cases[0].1;
        r[5] = 4;
        assert!(checked_copy(&r, array, u64::MAX).is_err());
        let mut r = cases[1].1;
        r[9] = 2;
        assert!(checked_copy(&r, volume, u64::MAX).is_err());
    }
    #[test]
    fn self_copies_and_flipped_blits_distinguish_mips_layers_and_volume() {
        let s = ImageShape {
            mips: 4,
            layers: 6,
            ..ImageShape::d2(8, 8, vk::Format::R8G8B8A8_UNORM)
        };
        let mut wire = [1, 0, 0, 2, 0, 0, 0, 8, 8, 1, 1, 1, 2, 2, 4, 0, 0, 0, 4, 1];
        let b = checked_blit(&wire, s, s).unwrap();
        assert!(!blit_overlap(&b, &b));
        wire[11] = 0;
        wire[12] = 0;
        let overlap = checked_blit(&wire, s, s).unwrap();
        assert!(blit_overlap(&overlap, &overlap));
        wire[17] = 9;
        assert!(checked_blit(&wire, s, s).is_err());
        let c = [1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 4, 4, 1];
        let copy = checked_image_copy(&c, s, s).unwrap();
        assert!(!copy_overlap(&copy, &copy));
        let mut c = c;
        c[8] = 0;
        let copy = checked_image_copy(&c, s, s).unwrap();
        assert!(copy_overlap(&copy, &copy));
        c[9] = 1;
        let copy = checked_image_copy(&c, s, s).unwrap();
        assert!(!copy_overlap(&copy, &copy));
    }
    #[test]
    fn image_copy_bounds_and_depth_compatibility() {
        let image = ImageShape::d2(8, 8, vk::Format::R8G8B8A8_UNORM);
        let valid = [1, 0, 0, 1, 1, 2, 0, 1, 0, 0, 1, 3, 4, 0, 4, 4, 1];
        assert!(checked_image_copy(&valid, image, image).is_ok());
        for (field, value) in [
            (0, 2),
            (1, 1),
            (3, 2),
            (4, u64::MAX),
            (6, 1),
            (7, 2),
            (11, 5),
            (12, 5),
            (14, 0),
            (16, 2),
        ] {
            let mut bad = valid;
            bad[field] = value;
            assert!(checked_image_copy(&bad, image, image).is_err());
        }
        let depth = ImageShape {
            format: vk::Format::D16_UNORM,
            ..image
        };
        assert!(checked_image_copy(&valid, image, depth).is_err());
        let mut copy = valid;
        copy[0] = 2;
        copy[7] = 2;
        assert!(checked_image_copy(&copy, depth, depth).is_ok());
        let other = ImageShape {
            format: vk::Format::D32_SFLOAT,
            ..depth
        };
        assert!(checked_image_copy(&copy, depth, other).is_err());
    }
    #[test]
    fn viewports_may_extend_outside_the_framebuffer() {
        let valid_viewport = |v: &[f32], maintenance1| {
            valid_viewport(v, maintenance1, [4096, 4096], [-32768.0, 32767.0])
        };
        assert!(valid_viewport(
            &[-64.0, 144.0, 256.0, -192.0, 0.0, 1.0],
            true
        ));
        assert!(valid_viewport(
            &[-64.0, -48.0, 256.0, 192.0, 0.0, 1.0],
            false
        ));
    }
    #[test]
    fn maintenance1_negative_viewports_use_native_bounds() {
        let valid_viewport = |v: &[f32], maintenance1| {
            valid_viewport(v, maintenance1, [4096, 4096], [-32768.0, 32767.0])
        };
        let flipped = [0.0, 192.0, 256.0, -192.0, 0.0, 1.0];
        assert!(valid_viewport(&flipped, true));
        assert!(valid_viewport(&[0.0, 0.0, 256.0, 0.0, 0.0, 1.0], true));
        assert!(!valid_viewport(&flipped, false));
        assert!(valid_viewport(&[0.0, 0.0, 256.0, 192.0, 0.0, 1.0], false));
        for (field, value) in [
            (0, f32::NAN),
            (1, -32769.0),
            (2, 0.0),
            (3, -4097.0),
            (4, -0.1),
            (5, 1.1),
        ] {
            let mut invalid = flipped;
            invalid[field] = value;
            assert!(!valid_viewport(&invalid, true));
        }
    }
    #[test]
    fn copy_checks_padded_rows_offsets_overflow_and_color_subresources() {
        let s = ImageShape::d2(64, 32, vk::Format::R8G8B8A8_UNORM);
        let valid = [16, 80, 32, 1, 0, 0, 1, 0, 0, 0, 64, 32, 1];
        let bytes = 16 + (31 * 80 + 64) * 4;
        assert!(checked_copy(&valid, s, bytes).is_ok());
        assert!(checked_copy(&valid, s, bytes - 1).is_err());
        for (at, value) in [
            (0, 3),
            (1, 63),
            (2, 31),
            (3, 2),
            (4, 1),
            (5, 1),
            (6, 2),
            (7, 1),
            (8, 1),
            (9, 1),
            (10, 0),
            (11, 0),
            (12, 2),
            (0, u64::MAX),
            (1, u64::MAX),
        ] {
            let mut x = valid;
            x[at] = value;
            assert!(checked_copy(&x, s, u64::MAX).is_err());
        }
    }
    #[test]
    fn image_profile_reports_only_supported_formats_usages_and_layouts() {
        assert!(format(37).is_ok());
        assert!(format(44).is_ok());
        assert_eq!(format(126).unwrap(), vk::Format::D32_SFLOAT);
        assert!(is_depth_stencil(vk::Format::D32_SFLOAT));
        assert!(is_depth_stencil(vk::Format::D16_UNORM));
        assert!(!is_depth_stencil(vk::Format::R8G8B8A8_UNORM));
        assert_eq!(format(127).unwrap(), vk::Format::S8_UINT);
        assert!(usage(vk::ImageUsageFlags::COLOR_ATTACHMENT.as_raw() as u64).is_ok());
        assert!(usage(vk::ImageUsageFlags::SAMPLED.as_raw() as u64).is_ok());
        assert!(usage(0).is_err());
        assert!(usage(1 << 40).is_err());
        assert!(layout(0, true).is_ok());
        assert!(layout(0, false).is_err());
        assert!(layout(1000001002, false).is_ok());
    }
    #[test]
    fn copy_footprints_follow_actual_texels_and_depth_aspects() {
        let copy = [0, 7, 4, 1, 0, 0, 1, 0, 0, 0, 5, 3, 1];
        for (format, bytes) in [
            (9, 1),
            (16, 2),
            (23, 3),
            (37, 4),
            (84, 6),
            (97, 8),
            (106, 12),
            (109, 16),
            (124, 2),
            (126, 4),
        ] {
            let image = ImageShape::d2(5, 3, self::format(format).unwrap());
            let mut region = copy;
            if is_depth_stencil(image.format) {
                region[3] = 2;
            }
            let required = (2 * 7 + 5) * bytes;
            assert!(
                checked_copy(&region, image, required).is_ok(),
                "format {format}"
            );
            assert!(checked_copy(&region, image, required - 1).is_err());
            let mut wrong_aspect = region;
            wrong_aspect[3] = if region[3] == 1 { 2 } else { 1 };
            assert!(checked_copy(&wrong_aspect, image, required).is_err());
        }
        assert!(
            format(110).is_err(),
            "64-bit channels remain outside the profile"
        );
        assert_eq!(compressed_block(131), Some((4, 4, 8)));
    }
    #[test]
    fn compressed_copy_footprints_use_blocks_mip_edges_and_array_strides() {
        for raw in 131..=184 {
            let (bw, bh, bytes) = compressed_block(raw).unwrap();
            let mut image = ImageShape::d2((bw + 1) as u32, (bh + 1) as u32, format(raw).unwrap());
            image.layers = 2;
            let region = [0, 0, 0, 1, 0, 0, 2, 0, 0, 0, bw + 1, bh + 1, 1];
            assert!(checked_copy(&region, image, 8 * bytes).is_ok(), "format {raw}");
            assert!(checked_copy(&region, image, 8 * bytes - 1).is_err());
            let mut padded = region;
            padded[1] = 3 * bw; padded[2] = 3 * bh;
            assert!(checked_copy(&padded, image, 14 * bytes).is_ok());
            assert!(checked_copy(&padded, image, 14 * bytes - 1).is_err());
            let mut partial = region;
            partial[7] = bw; partial[8] = bh; partial[10] = 1; partial[11] = 1;
            assert!(checked_copy(&partial, image, 2 * bytes).is_ok());
            for (field, value) in [(0, 4), (1, bw + 1), (2, bh + 1), (7, 1), (8, 1), (10, 1), (11, 1)] {
                let mut bad = region; bad[field] = value;
                assert!(checked_copy(&bad, image, u64::MAX).is_err(), "format {raw}, field {field}");
            }
            image.mips = 2;
            let mip = [0, 0, 0, 1, 1, 0, 1, 0, 0, 0, bw.div_ceil(2), bh.div_ceil(2), 1];
            assert!(checked_copy(&mip, image, bytes).is_ok());
        }
    }
    #[test]
    fn indirect_arguments_keep_vulkan_zero_and_single_draw_stride_rules() {
        assert!(indirect_span(64, 64, 0, 3, 16).is_ok());
        assert!(indirect_span(16, 0, 1, 3, 16).is_ok());
        assert!(indirect_span(40, 0, 2, 20, 20).is_ok());
        assert!(indirect_span(39, 0, 2, 20, 20).is_err());
        assert!(indirect_span(64, 2, 1, 0, 12).is_err());
        assert!(indirect_span(64, 0, 2, 12, 16).is_err());
        assert!(indirect_span(u64::MAX, 0, u64::MAX, 16, 16).is_err());
    }
    #[test]
    fn packed_depth_stencil_aspects_and_exact_copy_footprints() {
        for raw in 124..=130 {
            let s = ImageShape::d2(5, 3, format(raw).unwrap());
            assert!(vertex_size(raw).is_none());
            assert!(format_usage(s.format, 32 | 3 | 4).is_ok());
            assert!(format_usage(s.format, 16).is_err());
            for aspect in [1, 2, 4, 6] {
                let valid = aspect & !(s.aspect().as_raw() as u64) == 0;
                assert_eq!(s.range(&[aspect, 0, 1, 0, 1]).is_ok(), valid);
                let r = [16, 7, 4, aspect, 0, 0, 1, 0, 0, 0, 5, 3, 1];
                if valid && aspect != 6 {
                    let bytes = aspect_bytes(s.format, aspect).unwrap();
                    let required = 16 + (2 * 7 + 5) * bytes;
                    assert!(checked_copy(&r, s, required).is_ok());
                    assert!(checked_copy(&r, s, required - 1).is_err());
                } else {
                    assert!(checked_copy(&r, s, u64::MAX).is_err());
                }
            }
        }
        let s = ImageShape::d2(5, 3, vk::Format::D32_SFLOAT_S8_UINT);
        let mut copy = [2, 0, 0, 1, 0, 0, 0, 4, 0, 0, 1, 0, 0, 0, 5, 3, 1];
        assert!(checked_image_copy(&copy, s, s).is_err());
        copy[7] = 2;
        assert!(checked_image_copy(&copy, s, s).is_ok());
        copy[0] = 6;
        copy[7] = 6;
        assert!(checked_image_copy(&copy, s, s).is_ok());
        assert!(s.range(&[0, 0, 1, 0, 1]).is_err());
    }
    #[test]
    fn stencil_wire_checks_ops_masks_and_references() {
        let wire = [7, 6, 5, 4, u32::MAX as u64, 0x83, 0x42];
        let s = stencil_state(&wire).unwrap();
        assert_eq!(s.fail_op, vk::StencilOp::DECREMENT_AND_WRAP);
        assert_eq!(s.pass_op, vk::StencilOp::INCREMENT_AND_WRAP);
        assert_eq!(s.depth_fail_op, vk::StencilOp::INVERT);
        assert_eq!(s.compare_op, vk::CompareOp::GREATER);
        assert_eq!(
            (s.compare_mask, s.write_mask, s.reference),
            (u32::MAX, 0x83, 0x42)
        );
        for i in 0..7 {
            let mut bad = wire;
            bad[i] = if i < 4 { 8 } else { 1 << 32 };
            assert!(stencil_state(&bad).is_err());
        }
    }
}
