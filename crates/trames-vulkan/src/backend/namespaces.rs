// SPDX-License-Identifier: GPL-3.0-or-later
//! Original instance/device ownership within the existing exclusive Context.
//! No resource thread or new lock: all Rc graphs move in the same envelope.
use super::*;

impl Backend {
    fn configured_graph(&self) -> Self {
        let mut graph = Self::with_budget(self.budget.clone());
        graph.display = self.display.clone();
        graph.native_images = self.native_images;
        graph.completion = self.completion.clone();
        graph.wayland.server = self.wayland.server.clone();
        graph
    }
    fn device_graph(&self) -> Self {
        let mut graph = self.configured_graph();
        graph.device_graph = true;
        graph.instance = self.instance.clone();
        graph.instance_id = self.instance_id;
        graph.physical = self.physical;
        graph.physical_id = self.physical_id;
        graph.capabilities = self.capabilities.clone();
        graph.wsi_enabled = self.wsi_enabled;
        graph.virtual_wsi = self.virtual_wsi;
        graph
    }
    pub(super) fn finished_graph(&self) -> bool {
        (self.instance.is_none() || self.device_graph && self.device.is_none())
            && self.compiles.is_empty()
            && self.teardowns.is_empty()
            && self.submissions.is_empty()
            && self.waits.is_empty()
            && self.acquires.is_empty()
    }
    fn release_surface_copies(
        &mut self,
        operation: u64,
        a: [u64; 16],
        result: &std::result::Result<Invocation, MemoryError>,
    ) {
        if operation == 82 && matches!(result, Ok(Invocation::Complete(0))) {
            // Device graphs cache only the original instance's capability at
            // swapchain creation. The swapchain's Rc keeps in-flight use alive.
            for graph in self.graphs.values_mut() {
                graph.wsi.surfaces.remove(&a[1]);
                graph.wayland.surfaces.remove(&a[1]);
            }
        }
    }
    pub(super) fn invoke_graph(
        &mut self,
        memory: &mut impl CpuMemory,
        operation: u64,
        a: [u64; 16],
    ) -> std::result::Result<Invocation, MemoryError> {
        // The transport consumes the packet once. The normal graph remains
        // inline; only additional original instances/devices enter this map.
        if operation == 1 && self.instance.is_some() {
            let mut graph = self.configured_graph();
            let result = graph.execute(memory, operation, a);
            if matches!(result, Ok(Invocation::Complete(0))) {
                self.graphs.insert(graph.domain, Box::new(graph));
            }
            return result;
        }
        let domain = a[0] >> 32;
        if operation == 8 {
            let parent = if domain == self.domain {
                Some(&*self)
            } else {
                self.graphs.get(&domain).map(Box::as_ref)
            };
            if let Some(parent) = parent.filter(|parent| parent.device.is_some()) {
                let mut graph = parent.device_graph();
                let result = graph.execute(memory, operation, a);
                if matches!(result, Ok(Invocation::Complete(0))) {
                    self.graphs.insert(graph.domain, Box::new(graph));
                }
                return result;
            }
        }
        if domain != self.domain
            && !matches!(operation, 1 | 79 | 109)
            && self.graphs.contains_key(&domain)
        {
            // Surface ownership belongs to its original instance. A second
            // device captures that same Rc only at cold swapchain creation.
            let surface = if operation == 87 {
                let instance = self.graphs[&domain].instance_id;
                let parent = if instance >> 32 == self.domain {
                    Some(&*self)
                } else {
                    self.graphs.get(&(instance >> 32)).map(Box::as_ref)
                };
                parent.map(|parent| {
                    (
                        parent.wsi.surfaces.get(&a[1]).cloned(),
                        parent.wayland.surfaces.get(&a[1]).cloned(),
                    )
                })
            } else {
                None
            };
            let images = self.image_files.clone();
            let authentication = self.wayland.authenticated.clone();
            let graph = self.graphs.get_mut(&domain).unwrap();
            if let Some((native, wayland)) = surface {
                if let Some(surface) = native {
                    graph.wsi.surfaces.insert(a[1], surface);
                }
                if let Some(surface) = wayland {
                    graph.wayland.surfaces.insert(a[1], surface);
                }
            }
            graph.image_files = images;
            graph.wayland.authenticated = authentication;
            let before = graph.transfers;
            let result = graph.execute(memory, operation, a);
            graph.image_files = None;
            graph.wayland.authenticated = None;
            self.transfers.merge(graph.transfers.since(before));
            self.completion_notice |= std::mem::take(&mut graph.completion_notice);
            if graph.finished_graph() {
                self.graphs.remove(&domain);
            }
            self.release_surface_copies(operation, a, &result);
            return result;
        }
        let result = self.execute(memory, operation, a);
        self.release_surface_copies(operation, a, &result);
        result
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    const OUT: u64 = 0x2000;
    fn call(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> Invocation {
        let mut a = [0; 16];
        a[..args.len()].copy_from_slice(args);
        b.invoke_graph(m, op, a).unwrap()
    }
    fn ok(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> u64 {
        assert_eq!(call(b, m, op, args), Invocation::Complete(0));
        m.read_u64(OUT).unwrap()
    }
    fn physical(b: &mut Backend, m: &mut Memory, instance: u64) -> u64 {
        m.write_array(0x2100, 1u32.to_le_bytes()).unwrap();
        ok(b, m, 3, &[instance, 0x2100, OUT])
    }
    #[test]
    #[ignore = "requires the original native MoltenVK device/fence adapter"]
    fn hardware_original_instances_devices_and_pending_jobs_keep_their_owner() {
        let mut b = Backend::new();
        let mut m = Memory::default();
        m.map(0x1000, 0x4000, Permissions::RW).unwrap();
        let i1 = ok(&mut b, &mut m, 1, &[OUT]);
        let p1 = physical(&mut b, &mut m, i1);
        let i2 = ok(&mut b, &mut m, 1, &[OUT]);
        let p2 = physical(&mut b, &mut m, i2);
        assert_ne!(p1 >> 32, p2 >> 32);
        let d1 = ok(&mut b, &mut m, 8, &[p1, 0, OUT]);
        let d2 = ok(&mut b, &mut m, 8, &[p1, 0, OUT]);
        let d3 = ok(&mut b, &mut m, 8, &[p2, 0, OUT]);
        assert_eq!(b.graphs.len(), 2);
        let f1 = ok(&mut b, &mut m, 48, &[d1, 0, OUT]);
        let f2 = ok(&mut b, &mut m, 48, &[d2, 0, OUT]);
        let f3 = ok(&mut b, &mut m, 48, &[d3, 0, OUT]);
        assert_ne!(call(&mut b, &mut m, 50, &[d2, f1]), Invocation::Complete(0));
        m.write_array(0x2200, f1.to_le_bytes()).unwrap();
        let Invocation::Pending(j1) = call(&mut b, &mut m, 201, &[d1, 0x2200, 1, 1, u64::MAX])
        else {
            panic!("original fence must park")
        };
        m.write_array(0x2200, f2.to_le_bytes()).unwrap();
        let Invocation::Pending(j2) = call(&mut b, &mut m, 201, &[d2, 0x2200, 1, 1, u64::MAX])
        else {
            panic!("second device fence must park")
        };
        assert_ne!(j1 >> 32, j2 >> 32);
        assert_eq!(b.poll(&mut m, j1).unwrap(), None);
        assert_eq!(b.poll(&mut m, j2).unwrap(), None);
        b.abandon(j2);
        assert!(b.graphs[&(d2 >> 32)].waits.is_empty());
        let q1 = ok(&mut b, &mut m, 10, &[d1, 0, 0, OUT]);
        ok(&mut b, &mut m, 52, &[d1, q1, 0, 0, f1]);
        unsafe { b.device.as_ref().unwrap().native.device_wait_idle() }.unwrap();
        assert_eq!(b.poll(&mut m, j1).unwrap(), Some(0));
        ok(&mut b, &mut m, 49, &[d1, f1]);
        ok(&mut b, &mut m, 49, &[d2, f2]);
        ok(&mut b, &mut m, 9, &[d2]);
        assert!(!b.graphs.contains_key(&(d2 >> 32)));
        ok(&mut b, &mut m, 9, &[d1]);
        ok(&mut b, &mut m, 2, &[i1]);
        // Destruction of the first instance cannot retarget another graph.
        ok(&mut b, &mut m, 50, &[d3, f3]);
        ok(&mut b, &mut m, 49, &[d3, f3]);
        ok(&mut b, &mut m, 9, &[d3]);
        ok(&mut b, &mut m, 2, &[i2]);
        assert!(b.graphs.is_empty());
    }
    #[test]
    #[ignore = "requires original native MoltenVK queues"]
    fn hardware_queues_keep_original_families_and_cross_queue_semaphores() {
        let mut b = Backend::new();
        let mut m = Memory::default();
        m.map(0x1000, 0x4000, Permissions::RW).unwrap();
        let i = ok(&mut b, &mut m, 1, &[OUT]);
        let p = physical(&mut b, &mut m, i);
        m.write_array(0x2200, 1.0f32.to_le_bytes()).unwrap();
        let records = [0u64, 1, 0x2200, 1, 1, 0x2200];
        m.write(
            0x2300,
            &records
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let d = ok(
            &mut b,
            &mut m,
            8,
            &[p, 0, OUT, 0, 0, 10, 0, 0, 0, 0x2300, 2],
        );
        let q0 = ok(&mut b, &mut m, 10, &[d, 0, 0, OUT]);
        let q1 = ok(&mut b, &mut m, 10, &[d, 1, 0, OUT]);
        assert_ne!(q0, q1);
        let semaphore = ok(&mut b, &mut m, 54, &[d, OUT, 1, 0]);
        let fence = ok(&mut b, &mut m, 48, &[d, 0, OUT]);
        m.write_array(0x2400, semaphore.to_le_bytes()).unwrap();
        m.write_array(
            0x2500,
            vk::PipelineStageFlags::ALL_COMMANDS.as_raw().to_le_bytes(),
        )
        .unwrap();
        m.write_array(0x2508, 1u64.to_le_bytes()).unwrap();
        let records = [
            0x2400u64, 1, 0x2500, 0, 0, 0, 0, 0x2508, 0, 0, 0, 0, 0, 0, 0x2400, 1, 0, 0x2508,
        ];
        m.write(
            0x2600,
            &records
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        // A wait may enter before a different queue signals. Aliasing both
        // guest queues onto one serial native queue would deadlock this case.
        ok(&mut b, &mut m, 120, &[d, q0, 0x2600, 1, fence]);
        ok(&mut b, &mut m, 120, &[d, q1, 0x2648, 1, 0]);
        unsafe { b.device.as_ref().unwrap().native.device_wait_idle() }.unwrap();
        assert!(Backend::fence_ready(&b.objects[&fence]).unwrap());
        let pool = ok(&mut b, &mut m, 34, &[d, 1, 0, OUT]);
        let command = ok(&mut b, &mut m, 36, &[d, pool, OUT, 0]);
        m.write(
            0x2700,
            &[0u32, 1]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let buffer = ok(&mut b, &mut m, 11, &[d, 256, 3, OUT, 1, 0x2700, 2]);
        ok(&mut b, &mut m, 13, &[d, buffer, OUT]);
        let extra = [0u64, 0, 0, 0, 0, 0, 0, 0, 0x2700, 2];
        m.write(
            0x2800,
            &extra
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for shared in [false, true] {
            let image = ok(
                &mut b,
                &mut m,
                60,
                &[
                    d,
                    37,
                    4,
                    4,
                    3,
                    OUT,
                    0,
                    if shared { 0x2800 } else { 0 },
                    if shared { u64::MAX - 2 } else { 0 },
                    0,
                    1,
                    1,
                    1,
                    1,
                    1,
                    0,
                ],
            );
            ok(&mut b, &mut m, 62, &[d, image, OUT]);
            let size = m.read_u64(OUT).unwrap();
            let bits = read32(&m, OUT + 16).unwrap();
            let memory = ok(
                &mut b,
                &mut m,
                14,
                &[d, size, u64::from(bits.trailing_zeros()), OUT],
            );
            ok(&mut b, &mut m, 63, &[d, image, memory, 0]);
            let families = if shared {
                [u64::from(vk::QUEUE_FAMILY_IGNORED); 2]
            } else {
                [0, 1]
            };
            let wire = [image, 0, 0, 0, 1, 1, 0, 1, 0, 1, families[0], families[1]];
            m.write(
                0x2900,
                &wire
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let command = b.objects[&command].clone();
            let native = b.image_barriers(&m, &command, 0x2900, 1, 12).unwrap();
            assert_eq!(native[0].src_queue_family_index, families[0] as u32);
            assert_eq!(native[0].dst_queue_family_index, families[1] as u32);
        }
        ok(&mut b, &mut m, 9, &[d]);
        ok(&mut b, &mut m, 2, &[i]);
    }
}
