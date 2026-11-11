// SPDX-License-Identifier: GPL-3.0-or-later
//! Virtual output densities follow host windows, with independent surface membership.
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
use wayland_server::{
    backend::GlobalId, protocol::wl_output, Client, DataInit, Dispatch, DisplayHandle,
    GlobalDispatch, New,
};

pub(crate) struct Outputs {
    pub default_scale: i32,
    globals: BTreeSet<i32>,
    resources: BTreeMap<i32, Vec<wl_output::WlOutput>>,
}
impl Default for Outputs {
    fn default() -> Self {
        Self {
            default_scale: 1,
            globals: BTreeSet::new(),
            resources: BTreeMap::new(),
        }
    }
}
impl State {
    pub(crate) fn ensure_output(&mut self, handle: &DisplayHandle, scale: i32) {
        if self.outputs.globals.insert(scale) {
            let _: GlobalId = handle.create_global::<Self, wl_output::WlOutput, _>(3, scale);
        }
    }
    pub(crate) fn surface_output(&mut self, id: u64, scale: i32) {
        let Some(surface) = self.surfaces.get_mut(&id) else {
            return;
        };
        if surface.preferred_scale == scale {
            return;
        }
        for (&density, outputs) in &mut self.outputs.resources {
            outputs.retain(Resource::is_alive);
            for output in outputs
                .iter()
                .filter(|o| same_connection(o, surface.connection))
            {
                if density == surface.preferred_scale {
                    surface.resource.leave(output);
                }
                if density == scale {
                    surface.resource.enter(output);
                }
            }
        }
        surface.preferred_scale = scale;
        if surface.resource.version() >= 6 {
            surface.resource.preferred_buffer_scale(scale);
        }
    }
    pub(crate) fn inherit_output(&mut self, id: u64) {
        let scale = self
            .surfaces
            .get(&id)
            .and_then(|s| s.parent)
            .and_then(|(parent, _, _)| self.surfaces.get(&parent))
            .map(|p| p.preferred_scale);
        if let Some(scale) = scale {
            self.surface_output(id, scale);
        }
    }
}
fn same_connection(output: &wl_output::WlOutput, connection: u64) -> bool {
    output.client().is_some_and(|c| {
        c.get_data::<ClientIdentity>()
            .is_some_and(|i| i.connection == connection)
    })
}
impl GlobalDispatch<wl_output::WlOutput, i32> for State {
    fn bind(
        state: &mut Self,
        _: &DisplayHandle,
        client: &Client,
        output: New<wl_output::WlOutput>,
        scale: &i32,
        init: &mut DataInit<'_, Self>,
    ) {
        let output = init.init(output, *scale);
        let (w, h) = state.viewport;
        output.geometry(
            // Density groups are distinct virtual outputs. Give them disjoint
            // logical origins: GTK/Firefox also match monitor configuration by
            // origin, so overlapping groups can turn 2x back into a false 1x
            // fractional scale. Surface-local geometry and input stay unchanged.
            (*scale - 1) * w as i32,
            0,
            260,
            195,
            wl_output::Subpixel::Unknown,
            "Trames".into(),
            format!("Host {scale}x"),
            wl_output::Transform::Normal,
        );
        output.mode(
            wl_output::Mode::Current | wl_output::Mode::Preferred,
            w as i32 * scale,
            h as i32 * scale,
            crate::frame::REFRESH_MILLIHERTZ,
        );
        if output.version() >= 2 {
            output.scale(*scale);
            output.done();
        }
        let connection = client
            .get_data::<ClientIdentity>()
            .map_or(0, |i| i.connection);
        for surface in state
            .surfaces
            .values()
            .filter(|s| s.connection == connection && s.preferred_scale == *scale)
        {
            surface.resource.enter(&output);
        }
        let resources = state.outputs.resources.entry(*scale).or_default();
        resources.retain(Resource::is_alive);
        resources.push(output);
    }
}
impl Dispatch<wl_output::WlOutput, i32> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        output: &wl_output::WlOutput,
        _: wl_output::Request,
        scale: &i32,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let Some(outputs) = state.outputs.resources.get_mut(scale) {
            outputs.retain(|o| o != output);
        }
    }
}
