// SPDX-License-Identifier: GPL-3.0-or-later
//! Selected neural-compute features: cached queries and owned device-create nodes.
//! No tensor data, shader rewriting or extra CPU/GPU synchronization lives here.
use super::*;

#[derive(Default)]
pub(super) struct Capabilities {
    pub extensions: u64,
    pub features: u64,
    pub api: u32,
    properties: BTreeMap<u32, Vec<u32>>,
}
macro_rules! compute_features {
    ($($member:ident: $ty:ident, $extension:literal, $first:literal => [$($bit:literal => $field:ident : $expose:literal),+];)+) => {
        #[derive(Default)]
        pub(super) struct Selected { $( $member: vk::$ty<'static>, )+ }
        impl Selected {
            pub fn new(caps: &Capabilities, extensions: u64, features: u64) -> Result<Self> {
                if extensions & !caps.extensions != 0 || features & !caps.features != 0 { return unsupported(); }
                let mut selected = Self::default();
                $(const _: () = assert!($first < 64);
                let mask = 0 $(| (1 << $bit))+;
                if features & mask != 0 && extensions & (1 << $extension) == 0 { return unsupported(); }
                $(selected.$member.$field = ((features >> $bit) & 1) as u32;)+)+
                // StorageBuffer storage class is a dependency of low-bit storage.
                if extensions & ((1 << 1) | (1 << 2)) != 0 && extensions & EXT_STORAGE_CLASS == 0 { return unsupported(); }
                Ok(selected)
            }
            pub fn chain<'a>(&'a mut self, extensions: u64, mut info: vk::DeviceCreateInfo<'a>) -> vk::DeviceCreateInfo<'a> {
                $(if extensions & (1 << $extension) != 0 { info = info.push_next(&mut self.$member); })+
                info
            }
        }
        fn query_features(caps: &mut Capabilities, query: &ash::khr::get_physical_device_properties2::Instance, physical: vk::PhysicalDevice) {
            $(if caps.extensions & (1 << $extension) != 0 {
                let mut native = vk::$ty::default();
                let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut native);
                unsafe { query.get_physical_device_features2(physical, &mut features); }
                $(if $expose && native.$field != 0 { caps.features |= 1 << $bit; })+
            })+
        }
    }
}
macro_rules! compute_properties {
    ($($ty:ident, $extension:expr => [$($field:ident $(.$method:ident())? $(as $cast:ty)?),+];)+) => {
        fn query_properties(caps: &mut Capabilities, query: &ash::khr::get_physical_device_properties2::Instance, physical: vk::PhysicalDevice) {
            $(if ($extension == 0 && caps.api >= vk::API_VERSION_1_1) || caps.extensions & $extension != 0 {
                let mut native = vk::$ty::default();
                let mut properties = vk::PhysicalDeviceProperties2::default().push_next(&mut native);
                unsafe { query.get_physical_device_properties2(physical, &mut properties); }
                let values = vec![$(native.$field$(.$method())? $(as $cast)?),+];
                caps.properties.insert(native.s_type.as_raw() as u32, values);
            })+
        }
    }
}
include!("compute_schema.rs");

fn executable_features(features: u64, moltenvk: bool, vendor: u32) -> u64 {
    if moltenvk && vendor == 0x106b {
        features & !(SHADER_SHARED_FLOAT32_ATOMICS | SHADER_SHARED_FLOAT32_ATOMIC_ADD)
    } else {
        features
    }
}

impl Capabilities {
    pub fn query(
        instance: &Instance,
        physical: vk::PhysicalDevice,
        ext: &[vk::ExtensionProperties],
    ) -> Self {
        let mut caps = Self {
            api: vk::API_VERSION_1_0,
            ..Self::default()
        };
        if !instance.queries2 {
            return caps;
        }
        let native = unsafe { instance.native.get_physical_device_properties(physical) };
        caps.api = native.api_version.min(vk::API_VERSION_1_1);
        for &(bit, name, minimum) in EXTENSIONS {
            if caps.api >= minimum
                && ext
                    .iter()
                    .any(|e| unsafe { std::ffi::CStr::from_ptr(e.extension_name.as_ptr()) == name })
            {
                caps.extensions |= bit;
            }
        }
        let query = ash::khr::get_physical_device_properties2::Instance::new(
            &instance._entry,
            &instance.native,
        );
        query_features(&mut caps, &query, physical);
        // The pinned Apple MoltenVK advertises this field, but native MSL
        // compilation rejects threadgroup atomic_float add and exchange.
        // Buffer atomics stay driver-backed; no CPU/CAS emulation.
        caps.features = executable_features(caps.features, cfg!(trames_moltenvk), native.vendor_id);
        query_properties(&mut caps, &query, physical);
        if let Some(p) = caps
            .properties
            .get_mut(&(vk::StructureType::PHYSICAL_DEVICE_SUBGROUP_PROPERTIES.as_raw() as u32))
        {
            p[1] &= (vk::ShaderStageFlags::VERTEX
                | vk::ShaderStageFlags::FRAGMENT
                | vk::ShaderStageFlags::COMPUTE)
                .as_raw();
        }
        if let Some(p) = caps.properties.get_mut(
            &(vk::StructureType::PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_PROPERTIES.as_raw() as u32),
        ) {
            // Only the compute pipeline ingress accepts subgroup stage controls.
            p[3] &= vk::ShaderStageFlags::COMPUTE.as_raw();
        }
        if caps.extensions & EXT_MAINTENANCE3 != 0 {
            let mut limits = vk::PhysicalDeviceMaintenance3Properties::default();
            let mut properties = vk::PhysicalDeviceProperties2::default().push_next(&mut limits);
            unsafe {
                query.get_physical_device_properties2(physical, &mut properties);
            }
            caps.properties.insert(
                limits.s_type.as_raw() as u32,
                vec![
                    limits.max_per_set_descriptors,
                    0,
                    limits.max_memory_allocation_size as u32,
                    (limits.max_memory_allocation_size >> 32) as u32,
                ],
            );
        }
        caps
    }
    pub fn write_property(&self, m: &mut impl CpuMemory, kind: u32, at: u64) -> Result<()> {
        let words = self
            .properties
            .get(&kind)
            .ok_or(Failure::Vk(vk::Result::ERROR_FEATURE_NOT_PRESENT))?;
        let bytes: Vec<_> = words.iter().flat_map(|v| v.to_le_bytes()).collect();
        write(m, at, &bytes)
    }
    pub fn extension_names(
        &self,
        bits: u64,
        names: &mut Vec<*const std::ffi::c_char>,
    ) -> Result<()> {
        if bits & !self.extensions != 0 {
            return unsupported();
        }
        for &(bit, name, _) in EXTENSIONS {
            if bits & bit != 0 {
                names.push(name.as_ptr());
            }
        }
        Ok(())
    }
    pub fn stage_controls(&self, features: u64, flags: u64, size: u64) -> Result<()> {
        if flags & !3 != 0
            || flags & 1 != 0 && features & SUBGROUP_SIZE_CONTROL == 0
            || flags & 2 != 0 && features & COMPUTE_FULL_SUBGROUPS == 0
        {
            return unsupported();
        }
        if size != 0 {
            let props = self
                .properties
                .get(
                    &(vk::StructureType::PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_PROPERTIES.as_raw()
                        as u32),
                )
                .ok_or(Failure::Vk(vk::Result::ERROR_FEATURE_NOT_PRESENT))?;
            if features & SUBGROUP_SIZE_CONTROL == 0
                || flags & 1 != 0
                || !size.is_power_of_two()
                || size < props[0] as u64
                || size > props[1] as u64
                || props[3] & vk::ShaderStageFlags::COMPUTE.as_raw() == 0
            {
                return unsupported();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apple_atomic_quirk_preserves_buffer_atomics_and_other_drivers() {
        let removed = SHADER_SHARED_FLOAT32_ATOMICS | SHADER_SHARED_FLOAT32_ATOMIC_ADD;
        assert_eq!(executable_features(u64::MAX, true, 0x106b), !removed);
        assert_eq!(executable_features(u64::MAX, false, 0x106b), u64::MAX);
        assert_eq!(executable_features(u64::MAX, true, 0x1002), u64::MAX);
    }
    #[test]
    fn compute_features_require_native_support_and_enabled_extensions() {
        let caps = Capabilities {
            extensions: u64::MAX,
            features: 1,
            ..Default::default()
        };
        assert!(Selected::new(&caps, 3, 1).is_ok());
        assert!(Selected::new(&caps, 0, 1).is_err());
        assert!(Selected::new(&caps, 3, 2).is_err());
        assert!(Selected::new(&caps, 2, 1).is_err());
        let absent = Capabilities::default();
        assert!(Selected::new(&absent, 1, 0).is_err());
    }
    #[test]
    fn subgroup_controls_do_not_invent_required_compute_sizes() {
        let mut caps = Capabilities::default();
        caps.properties.insert(
            vk::StructureType::PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_PROPERTIES.as_raw() as u32,
            vec![4, 32, 256, 0],
        );
        assert!(caps
            .stage_controls(SUBGROUP_SIZE_CONTROL | COMPUTE_FULL_SUBGROUPS, 3, 0)
            .is_ok());
        assert!(caps.stage_controls(SUBGROUP_SIZE_CONTROL, 0, 32).is_err());
        assert!(caps.stage_controls(0, 1, 0).is_err());
        assert!(caps.stage_controls(COMPUTE_FULL_SUBGROUPS, 4, 0).is_err());
    }
}
