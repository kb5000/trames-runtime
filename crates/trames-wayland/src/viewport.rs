// SPDX-License-Identifier: GPL-3.0-or-later
//! Double-buffered crop/scale metadata; original SHM/GPU storage stays retained.
use crate::{scene::SurfaceKey, State};
use wayland_protocols::wp::viewporter::server::{wp_viewport, wp_viewporter};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource};

#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) struct Viewport {
    pub source: Option<[f64; 4]>,
    pub destination: Option<(u32, u32)>,
}
impl Viewport {
    pub fn validate_size(self) -> Result<(), (u32, &'static str)> {
        if self.destination.is_none()
            && self
                .source
                .is_some_and(|[_, _, w, h]| w.fract() != 0.0 || h.fract() != 0.0)
        {
            return Err((1, "fractional source size needs a destination"));
        }
        Ok(())
    }
    pub fn size(self, buffer: (u32, u32)) -> Result<(u32, u32), (u32, &'static str)> {
        self.validate_size()?;
        if let Some([x, y, w, h]) = self.source {
            if x + w > f64::from(buffer.0) || y + h > f64::from(buffer.1) {
                return Err((2, "viewport source exceeds buffer"));
            }
        }
        Ok(self.destination.unwrap_or_else(|| {
            self.source
                .map(|[_, _, w, h]| (w as u32, h as u32))
                .unwrap_or(buffer)
        }))
    }
    pub fn normalized_source(self, buffer: (u32, u32)) -> [f32; 4] {
        self.source.map_or([0.0, 0.0, 1.0, 1.0], |[x, y, w, h]| {
            let (bw, bh) = (f64::from(buffer.0), f64::from(buffer.1));
            [
                (x / bw) as f32,
                (y / bh) as f32,
                (w / bw) as f32,
                (h / bh) as f32,
            ]
        })
    }
}
pub(crate) fn globals(handle: &DisplayHandle) {
    handle.create_global::<State, wp_viewporter::WpViewporter, _>(1, ());
}
impl GlobalDispatch<wp_viewporter::WpViewporter, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        id: New<wp_viewporter::WpViewporter>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(id, ());
    }
}
impl Dispatch<wp_viewporter::WpViewporter, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        resource: &wp_viewporter::WpViewporter,
        request: wp_viewporter::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wp_viewporter::Request::Destroy => {}
            wp_viewporter::Request::GetViewport { id, surface } => {
                let Some(key) = surface.data::<SurfaceKey>().copied() else {
                    init.post_error(id, 3u32, "missing surface");
                    return;
                };
                let Some(surface) = state.surfaces.get_mut(&key.0) else {
                    init.post_error(id, 3u32, "destroyed surface");
                    return;
                };
                if surface.viewport_resource.is_some() {
                    resource.post_error(0u32, "surface already has a viewport");
                    return;
                }
                surface.viewport_resource = Some(init.init(id, key));
            }
            _ => unreachable!(),
        }
    }
}
impl Dispatch<wp_viewport::WpViewport, SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        resource: &wp_viewport::WpViewport,
        request: wp_viewport::Request,
        key: &SurfaceKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let Some(surface) = state.surfaces.get_mut(&key.0) else {
            if !matches!(request, wp_viewport::Request::Destroy) {
                resource.post_error(3u32, "surface was destroyed");
            }
            return;
        };
        match request {
            wp_viewport::Request::Destroy => {
                surface.viewport_resource = None;
                surface.pending_viewport = Viewport::default();
            }
            wp_viewport::Request::SetSource {
                x,
                y,
                width,
                height,
            } => {
                surface.pending_viewport.source = if [x, y, width, height] == [-1.0; 4] {
                    None
                } else if x < 0.0 || y < 0.0 || width <= 0.0 || height <= 0.0 {
                    resource.post_error(0u32, "invalid viewport source");
                    return;
                } else {
                    Some([x, y, width, height])
                };
            }
            wp_viewport::Request::SetDestination { width, height } => {
                surface.pending_viewport.destination = if (width, height) == (-1, -1) {
                    None
                } else if width <= 0 || height <= 0 {
                    resource.post_error(0u32, "invalid viewport destination");
                    return;
                } else {
                    Some((width as u32, height as u32))
                };
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_crop_and_destination_are_independent() {
        let crop = Viewport {
            source: Some([10.5, 2.0, 60.0, 20.0]),
            destination: None,
        };
        assert_eq!(crop.size((100, 50)), Ok((60, 20)));
        assert_eq!(crop.normalized_source((100, 50)), [0.105, 0.04, 0.6, 0.4]);
        assert_eq!(
            Viewport {
                destination: Some((30, 10)),
                ..crop
            }
            .size((100, 50)),
            Ok((30, 10))
        );
        assert_eq!(
            Viewport {
                source: Some([0.0, 0.0, 60.5, 20.0]),
                ..crop
            }
            .size((100, 50))
            .unwrap_err()
            .0,
            1
        );
        assert_eq!(crop.size((50, 50)).unwrap_err().0, 2);
    }
}
