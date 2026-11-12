// SPDX-License-Identifier: GPL-3.0-or-later
//! Original dispatch tables, loaded once with their native device. State changes
//! and synchronous transfers never repeat vkGetDeviceProcAddr lookups.
use ash::{ext, khr};
pub(in crate::backend) struct NativeCommands {
    pub extended: ext::extended_dynamic_state::Device,
    pub extended2: ext::extended_dynamic_state2::Device,
    pub extended3: ext::extended_dynamic_state3::Device,
    pub samples: ext::sample_locations::Device,
    pub lines: ext::line_rasterization::Device,
    pub host_copy: ext::host_image_copy::Device,
    pub sync2: khr::synchronization2::Device,
    pub rendering: khr::dynamic_rendering::Device,
}
impl NativeCommands {
    pub(in crate::backend) fn new(instance: &ash::Instance, device: &ash::Device) -> Self {
        Self {
            extended: ext::extended_dynamic_state::Device::new(instance, device),
            extended2: ext::extended_dynamic_state2::Device::new(instance, device),
            extended3: ext::extended_dynamic_state3::Device::new(instance, device),
            samples: ext::sample_locations::Device::new(instance, device),
            lines: ext::line_rasterization::Device::new(instance, device),
            host_copy: ext::host_image_copy::Device::new(instance, device),
            sync2: khr::synchronization2::Device::new(instance, device),
            rendering: khr::dynamic_rendering::Device::new(instance, device),
        }
    }
}
