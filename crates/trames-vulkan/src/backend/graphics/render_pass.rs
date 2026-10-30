// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned single-subpass attachment metadata; arbitrary attachment order and
//! native color resolves. The legacy single-sample wire remains accepted.
use super::*;
type Decoded = (
    PassInfo,
    Vec<vk::AttachmentDescription>,
    Vec<vk::AttachmentReference>,
    vk::AttachmentReference,
    Vec<vk::AttachmentReference>,
);

pub(super) fn decode(backend: &Backend, m: &impl CpuMemory, at: u64) -> Result<Decoded> {
    let h = words64(m, at, 7)?;
    let count = bounded(h[0], MAX_ATTACHMENTS)?;
    let colors = bounded(h[2], MAX_COLORS)?;
    let mut pass = PassInfo::new(colors);
    let mut attachments = Vec::with_capacity(count);
    for (i, x) in words64(m, h[1], count * 9)?.chunks_exact(9).enumerate() {
        let f = format(x[0])?;
        if x[2] > 2 || x[3] > 1 || x[4] > 2 || x[5] > 1 || x[8] != 0 {
            return unsupported();
        }
        let aspects = format_aspects(f);
        if aspects.intersects(vk::ImageAspectFlags::COLOR | vk::ImageAspectFlags::DEPTH)
            && x[2] == 1
            || aspects.contains(vk::ImageAspectFlags::STENCIL) && x[4] == 1
        {
            pass.clear_count = pass.clear_count.max(i+1);
        }
        attachments.push(
            vk::AttachmentDescription::default()
                .format(f)
                .samples(sample_count(x[1])?)
                .load_op(vk::AttachmentLoadOp::from_raw(x[2] as i32))
                .store_op(vk::AttachmentStoreOp::from_raw(x[3] as i32))
                .stencil_load_op(vk::AttachmentLoadOp::from_raw(x[4] as i32))
                .stencil_store_op(vk::AttachmentStoreOp::from_raw(x[5] as i32))
                .initial_layout(backend.native_layout(x[6], true)?)
                .final_layout(backend.native_layout(x[7], false)?),
        );
    }
    let reference = |index: u64, layout: u64, depth: bool| -> Result<vk::AttachmentReference> {
        if index == vk::ATTACHMENT_UNUSED as u64 {
            return Ok(vk::AttachmentReference::default().attachment(vk::ATTACHMENT_UNUSED));
        }
        if index >= count as u64 || is_depth_stencil(attachments[index as usize].format) != depth {
            return invalid();
        }
        Ok(vk::AttachmentReference::default()
            .attachment(index as u32)
            .layout(attachment_reference_layout(layout, depth)?))
    };
    let mut references = Vec::with_capacity(colors);
    for (i, x) in words64(m, h[3], colors * 2)?.chunks_exact(2).enumerate() {
        let r = reference(x[0], x[1], false)?;
        if r.attachment != vk::ATTACHMENT_UNUSED {
            pass.colors[i] = attachments[r.attachment as usize].format;
        }
        references.push(r);
    }
    let depth = reference(h[5], h[6], true)?;
    if depth.attachment != vk::ATTACHMENT_UNUSED {
        pass.depth = Some(attachments[depth.attachment as usize].format);
    }
    let mut resolves = Vec::new();
    if h[4] != 0 {
        for (i, x) in words64(m, h[4], colors * 2)?.chunks_exact(2).enumerate() {
            let r = reference(x[0], x[1], false)?;
            if r.attachment != vk::ATTACHMENT_UNUSED {
                let src = references[i].attachment;
                if src == vk::ATTACHMENT_UNUSED {
                    return invalid();
                }
                let src = &attachments[src as usize];
                let dst = &attachments[r.attachment as usize];
                if src.samples == vk::SampleCountFlags::TYPE_1
                    || dst.samples != vk::SampleCountFlags::TYPE_1
                    || src.format != dst.format
                {
                    return invalid();
                }
            }
            resolves.push(r);
        }
    }
    Ok((pass, attachments, references, depth, resolves))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn noncanonical_attachment_order_retains_resolve_depth_samples_and_clears() {
        let mut m = Memory::default();
        m.map(0x1000, 4096, Permissions::RW).unwrap();
        let put =
            |m: &mut Memory, at, words: &[u64]| write_words(m, at, words, words.len() * 8).unwrap();
        put(&mut m, 0x1000, &[3, 0x1200, 1, 0x1400, 0x1500, 1, 3]);
        put(
            &mut m,
            0x1200,
            &[
                37, 1, 2, 0, 2, 1, 0, 6, 0, 126, 4, 1, 1, 2, 1, 0, 3, 0, 37, 4, 1, 0, 2, 1, 0, 6, 0,
            ],
        );
        put(&mut m, 0x1400, &[2, 2]);
        put(&mut m, 0x1500, &[0, 2]);
        let b = Backend::new();
        let (p, a, c, d, r) = decode(&b, &m, 0x1000).unwrap();
        assert_eq!((c[0].attachment, d.attachment, r[0].attachment), (2, 1, 0));
        assert_eq!(
            (a[2].samples, a[0].samples),
            (vk::SampleCountFlags::TYPE_4, vk::SampleCountFlags::TYPE_1)
        );
        assert_eq!(p.depth, Some(vk::Format::D32_SFLOAT));
        assert_eq!(p.clear_count, 3);
        // Resolve targets must be single-sampled and color formats must match.
        put(&mut m, 0x1208, &[4]);
        assert!(decode(&b, &m, 0x1000).is_err());
        put(&mut m, 0x1208, &[1]);
        put(&mut m, 0x1200, &[44]);
        assert!(decode(&b, &m, 0x1000).is_err());
        put(&mut m, 0x1000, &[18]);
        assert!(decode(&b, &m, 0x1000).is_err());
    }
}
