// SPDX-License-Identifier: GPL-3.0-or-later
//! Both guest renderpass APIs normalize to owned native renderpass2 records.
//! Attachment graphs retain input/preserve, multiview, independent stencil
//! layouts and depth/stencil resolves without per-product implementations.
use super::*;

#[derive(Default)]
struct References {
    values:Vec<vk::AttachmentReference2<'static>>,
    _stencil:Vec<vk::AttachmentReferenceStencilLayout<'static>>,
}
fn references(backend:&Backend,m:&impl CpuMemory,at:u64,count:u64,pass:&mut PassInfo,usage:vk::ImageUsageFlags)->Result<References> {
    let wire=descriptors::words(m,at,count,4)?;
    let mut stencil=vec![vk::AttachmentReferenceStencilLayout::default();wire.len()/4];let mut values=Vec::with_capacity(stencil.len());
    for (i,r) in wire.chunks_exact(4).enumerate() {
        if r[0]==vk::ATTACHMENT_UNUSED as u64 {values.push(vk::AttachmentReference2::default().attachment(vk::ATTACHMENT_UNUSED));continue;}
        let index=usize::try_from(r[0]).map_err(|_|Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
        if index>=pass.attachments {return invalid();}
        pass.usages[index]|=usage;
        let mut value=vk::AttachmentReference2::default().attachment(index as u32).layout(backend.native_layout(r[1],false)?)
            .aspect_mask(if r[2]==0 {format_aspects(pass.formats[index])}else{vk::ImageAspectFlags::from_raw(r[2] as u32)});
        if r[3]!=u32::MAX as u64 {
            if backend.device.as_ref().unwrap().compute_features&compute::SEPARATE_DEPTH_STENCIL_LAYOUTS==0 {return unsupported();}
            stencil[i].stencil_layout=backend.native_layout(r[3],false)?;
            // Buffers are fully allocated before native pointers are installed;
            // they remain owned until the synchronous original-driver call ends.
            value.p_next=(&stencil[i] as *const vk::AttachmentReferenceStencilLayout).cast();
        }
        values.push(value);
    }
    Ok(References{values,_stencil:stencil})
}
struct Subpass {
    colors:References,resolves:References,inputs:References,depth:References,depth_resolve:References,
    preserve:Vec<u32>,view_mask:u32,flags:u32,
    resolve:vk::SubpassDescriptionDepthStencilResolve<'static>,
}
fn signature(pass:&PassInfo,refs:&References)->Vec<(vk::Format,vk::SampleCountFlags)> {
    refs.values.iter().map(|r|if r.attachment==vk::ATTACHMENT_UNUSED {(vk::Format::UNDEFINED,vk::SampleCountFlags::empty())}else{(pass.formats[r.attachment as usize],pass.sample_counts[r.attachment as usize])}).collect()
}
impl Backend {
    pub(super) fn render_graph(&mut self,m:&mut impl CpuMemory,a:[u64;16])->Result<()> {
        self.room(1)?;output(m,a[2],8)?;
        let device=self.device.as_ref().unwrap().clone();if !device.renderpass2 || a[3]!=0 {return unsupported();}
        let h=words64(m,a[1],8)?;
        let rows=descriptors::words(m,h[1],h[0],11)?;
        let mut pass=PassInfo::new(0);pass.attachments=rows.len()/11;pass.formats.clear();pass.sample_counts.clear();pass.usages=vec![vk::ImageUsageFlags::empty();pass.attachments];pass.subpasses.clear();
        let mut stencil=vec![vk::AttachmentDescriptionStencilLayout::default();pass.attachments];let mut attachments=Vec::with_capacity(pass.attachments);
        for (i,r) in rows.chunks_exact(11).enumerate() {
            if r[2]>2 || r[3]>1 || r[4]>2 || r[5]>1 || r[8]&!1!=0 {return unsupported();}
            let format=format(r[0])?;let samples=sample_count(r[1])?;
            pass.formats.push(format);pass.sample_counts.push(samples);
            if format_aspects(format).intersects(vk::ImageAspectFlags::COLOR|vk::ImageAspectFlags::DEPTH)&&r[2]==1 || format_aspects(format).contains(vk::ImageAspectFlags::STENCIL)&&r[4]==1 {pass.clear_count=i+1;}
            let mut native=vk::AttachmentDescription2::default().flags(vk::AttachmentDescriptionFlags::from_raw(r[8] as u32)).format(format).samples(samples)
                .load_op(vk::AttachmentLoadOp::from_raw(r[2] as i32)).store_op(vk::AttachmentStoreOp::from_raw(r[3] as i32))
                .stencil_load_op(vk::AttachmentLoadOp::from_raw(r[4] as i32)).stencil_store_op(vk::AttachmentStoreOp::from_raw(r[5] as i32))
                .initial_layout(self.native_layout(r[6],true)?).final_layout(self.native_layout(r[7],false)?);
            if r[9]!=u32::MAX as u64 || r[10]!=u32::MAX as u64 {
                if device.compute_features&compute::SEPARATE_DEPTH_STENCIL_LAYOUTS==0 {return unsupported();}
                stencil[i].stencil_initial_layout=self.native_layout(r[9],true)?;stencil[i].stencil_final_layout=self.native_layout(r[10],false)?;
                native.p_next=(&stencil[i] as *const vk::AttachmentDescriptionStencilLayout).cast();
            }
            attachments.push(native);
        }
        let rows=descriptors::words(m,h[3],h[2],14)?;if rows.is_empty(){return invalid();}
        let mut owned=Vec::with_capacity(rows.len()/14);
        for r in rows.chunks_exact(14) {
            if r[0]!=0 || r[1]!=vk::PipelineBindPoint::GRAPHICS.as_raw() as u64 || r[3]>device.max_color_attachments as u64 || r[3]>MAX_COLORS as u64 || r[2]>u32::MAX as u64 {return unsupported();}
            let view_mask=r[2] as u32;
            if view_mask!=0 && (device.compute_features&compute::MULTIVIEW==0 || 32-view_mask.leading_zeros()>self.capabilities.compute.multiview_count()){return unsupported();}
            pass.view_mask|=view_mask;
            let colors=references(self,m,r[4],r[3],&mut pass,vk::ImageUsageFlags::COLOR_ATTACHMENT)?;
            let resolves=if r[5]==0 {References::default()}else{references(self,m,r[5],r[3],&mut pass,vk::ImageUsageFlags::COLOR_ATTACHMENT)?};
            let inputs=references(self,m,r[7],r[6],&mut pass,vk::ImageUsageFlags::INPUT_ATTACHMENT)?;
            let depth=references(self,m,r[8],u64::from(r[8]!=0),&mut pass,vk::ImageUsageFlags::DEPTH_STENCIL_ATTACHMENT)?;
            let depth_resolve=references(self,m,r[13],u64::from(r[13]!=0),&mut pass,vk::ImageUsageFlags::DEPTH_STENCIL_ATTACHMENT)?;
            let preserve=descriptors::words32(m,r[10],r[9])?;
            if preserve.iter().any(|&index|index as usize>=pass.attachments){return invalid();}
            let mut info=SubpassInfo::new(colors.values.len());info.view_mask=view_mask;
            for (i,c) in colors.values.iter().enumerate(){if c.attachment!=vk::ATTACHMENT_UNUSED {info.colors[i]=pass.formats[c.attachment as usize];}}
            for reference in colors.values.iter().chain(&depth.values) {
                if reference.attachment==vk::ATTACHMENT_UNUSED {continue;}
                let samples=pass.sample_counts[reference.attachment as usize];
                if !info.samples.is_empty() && info.samples!=samples{return invalid();}info.samples=samples;
            }
            if let Some(d)=depth.values.first().filter(|r|r.attachment!=vk::ATTACHMENT_UNUSED){info.depth=Some(pass.formats[d.attachment as usize]);}
            for (c,t) in colors.values.iter().zip(&resolves.values) {
                if t.attachment==vk::ATTACHMENT_UNUSED {continue;}
                if c.attachment==vk::ATTACHMENT_UNUSED || pass.sample_counts[c.attachment as usize]==vk::SampleCountFlags::TYPE_1 || pass.sample_counts[t.attachment as usize]!=vk::SampleCountFlags::TYPE_1 {return invalid();}
            }
            info.inputs=signature(&pass,&inputs);info.resolves=signature(&pass,&resolves);
            if let Some(target)=depth_resolve.values.first().filter(|r|r.attachment!=vk::ATTACHMENT_UNUSED) {
                if info.depth.is_none() || info.samples==vk::SampleCountFlags::TYPE_1 || pass.sample_counts[target.attachment as usize]!=vk::SampleCountFlags::TYPE_1 {return invalid();}
                self.capabilities.compute.resolve_modes(r[11] as u32,r[12] as u32)?;
                info.depth_resolve=Some((pass.formats[target.attachment as usize],r[11] as u32,r[12] as u32));
            }
            pass.subpasses.push(info);
            owned.push(Subpass {colors,resolves,inputs,depth,depth_resolve,preserve,view_mask,flags:r[0] as u32,
                resolve:vk::SubpassDescriptionDepthStencilResolve::default().depth_resolve_mode(vk::ResolveModeFlags::from_raw(r[11] as u32)).stencil_resolve_mode(vk::ResolveModeFlags::from_raw(r[12] as u32))});
        }
        if pass.view_mask!=0 && pass.subpasses.iter().any(|s|s.view_mask==0){return invalid();}
        let subpass_count=owned.len();
        let mut subpasses=Vec::with_capacity(subpass_count);
        for s in &mut owned {
            let mut native=vk::SubpassDescription2::default().flags(vk::SubpassDescriptionFlags::from_raw(s.flags)).pipeline_bind_point(vk::PipelineBindPoint::GRAPHICS).view_mask(s.view_mask)
                .color_attachments(&s.colors.values).input_attachments(&s.inputs.values).preserve_attachments(&s.preserve);
            if !s.resolves.values.is_empty(){native=native.resolve_attachments(&s.resolves.values);}
            if let Some(depth)=s.depth.values.first(){native=native.depth_stencil_attachment(depth);}
            if let Some(target)=s.depth_resolve.values.first(){s.resolve.p_depth_stencil_resolve_attachment=target;native.p_next=(&s.resolve as *const vk::SubpassDescriptionDepthStencilResolve).cast();}
            subpasses.push(native);
        }
        let mut deps=Vec::new();
        for r in descriptors::words(m,h[5],h[4],8)?.chunks_exact(8) {
            if r[0]!=vk::SUBPASS_EXTERNAL as u64 && r[0]>=subpass_count as u64 || r[1]!=vk::SUBPASS_EXTERNAL as u64 && r[1]>=subpass_count as u64 || r[6]&!7!=0{return invalid();}
            deps.push(vk::SubpassDependency2::default().src_subpass(r[0] as u32).dst_subpass(r[1] as u32).src_stage_mask(device.stage(r[2] as u32)?).dst_stage_mask(device.stage(r[3] as u32)?)
                .src_access_mask(vk::AccessFlags::from_raw(r[4] as u32)).dst_access_mask(vk::AccessFlags::from_raw(r[5] as u32)).dependency_flags(vk::DependencyFlags::from_raw(r[6] as u32)).view_offset(r[7] as i32));
        }
        let correlations=descriptors::words32(m,h[7],h[6])?;
        let info=vk::RenderPassCreateInfo2::default().attachments(&attachments).subpasses(&subpasses).dependencies(&deps).correlated_view_masks(&correlations);
        let api=ash::khr::create_renderpass2::Device::new(&device.instance.native,&device.native);
        let raw=unsafe {api.create_render_pass2(&info,None)}?;
        let id=self.put(Kind::RenderPass,raw.as_raw(),Vec::new(),0,0);self.objects[&id].pass.set(Box::new(pass)).expect("new renderpass graph");self.publish(m,a[2],id)
    }
}
