// SPDX-License-Identifier: GPL-3.0-or-later
//! Vulkan 1.1 plane-compatible formats, matching Vulkan-Headers 1.3.281.
//! Plane transfers use their native compatible format and subsampled extent;
//! the original GPU driver performs reconstruction and color conversion.
use super::*;

pub(super) fn plane(raw: u64, aspect: u64) -> Option<(u64, u32, u32)> {
    if !(1000156000..=1000156033).contains(&raw) {
        return None;
    }
    let offset = raw - 1000156000;
    let (kind, r, rg) = match offset {
        2..=6 => (offset - 2, 9, 16),
        12..=16 => (offset - 12, 1000156007, 1000156008),
        22..=26 => (offset - 22, 1000156017, 1000156018),
        29..=33 => (offset - 29, 70, 77),
        _ => return None,
    };
    let index = match aspect {
        16 => 0,
        32 => 1,
        64 => 2,
        _ => return None,
    };
    let two = kind == 1 || kind == 3;
    if index >= if two { 2 } else { 3 } {
        return None;
    }
    let (x, y) = if index == 0 {
        (1, 1)
    } else {
        (if kind == 4 { 1 } else { 2 }, if kind < 2 { 2 } else { 1 })
    };
    Some((if index == 1 && two { rg } else { r }, x, y))
}
pub(super) fn multiplane(raw: u64) -> bool {
    plane(raw, 16).is_some()
}
pub(super) fn packed(raw: u64) -> Option<(u64, u64, u64)> {
    Some(match raw {
        1000156000 | 1000156001 => (2, 1, 4),
        1000156010 | 1000156011 | 1000156020 | 1000156021 | 1000156027 | 1000156028 => (2, 1, 8),
        1000156007 | 1000156017 => (1, 1, 2),
        1000156008 | 1000156018 => (1, 1, 4),
        1000156009 | 1000156019 => (1, 1, 8),
        _ => return None,
    })
}
pub(super) fn transfer_format(format: vk::Format, aspect: u64) -> Result<vk::Format> {
    if multiplane(format.as_raw() as u64) {
        plane(format.as_raw() as u64, aspect)
            .map(|p| vk::Format::from_raw(p.0 as i32))
            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))
    } else {
        Ok(format)
    }
}
impl Backend {
    pub(in crate::backend) fn conversion_call(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        if op == 231 {
            return self.remove(a[1], Kind::YcbcrConversion);
        }
        self.room(1)?;
        output(m, a[2], 8)?;
        let device = self.device(a[0])?;
        if device.compute_features & compute::SAMPLER_YCBCR_CONVERSION == 0 {
            return unsupported();
        }
        let w = words64(m, a[1], 11)?;
        if w[1] > 4 || w[2] > 1 || w[3..7].iter().any(|&v| v > 6) || w[7..11].iter().any(|&v| v > 1)
        {
            return invalid();
        }
        let component = |n: usize| vk::ComponentSwizzle::from_raw(w[n] as i32);
        let info = vk::SamplerYcbcrConversionCreateInfo::default()
            .format(format(w[0])?)
            .ycbcr_model(vk::SamplerYcbcrModelConversion::from_raw(w[1] as i32))
            .ycbcr_range(vk::SamplerYcbcrRange::from_raw(w[2] as i32))
            .components(vk::ComponentMapping {
                r: component(3),
                g: component(4),
                b: component(5),
                a: component(6),
            })
            .x_chroma_offset(vk::ChromaLocation::from_raw(w[7] as i32))
            .y_chroma_offset(vk::ChromaLocation::from_raw(w[8] as i32))
            .chroma_filter(vk::Filter::from_raw(w[9] as i32))
            .force_explicit_reconstruction(w[10] != 0);
        let api = ash::khr::sampler_ycbcr_conversion::Device::new(
            &device.instance.native,
            &device.native,
        );
        let raw = unsafe { api.create_sampler_ycbcr_conversion(&info, None) }?;
        let id = self.put(Kind::YcbcrConversion, raw.as_raw(), Vec::new(), w[0], 0);
        self.publish(m, a[2], id)
    }
}
