// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-only clipboard offers. FDs pass directly between Wayland clients;
//! this never reads or writes the host OS clipboard.
use super::*;
use std::{os::fd::AsFd, sync::Mutex};
use wayland_server::protocol::{
    wl_data_device as device, wl_data_device_manager as manager, wl_data_offer as offer,
    wl_data_source as source,
};
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, WEnum};

#[derive(Default)]
pub(crate) struct Selection {
    source: Option<source::WlDataSource>,
    pub(crate) host: Option<Arc<dyn HostClipboard>>,
    devices: Vec<device::WlDataDevice>,
    handle: Option<DisplayHandle>,
}
#[derive(Default)]
pub(crate) struct SourceData {
    mimes: Mutex<Vec<String>>,
}
pub(crate) struct OfferData {
    source: Option<source::WlDataSource>,
}
pub trait HostClipboard: Send + Sync {
    fn changed(&self) {}
    fn read(&self, fd: std::os::fd::OwnedFd) -> io::Result<()>;
    fn write(&self, pipe: trames_shared::NativePipe) -> io::Result<()>;
}
const TEXT_MIMES: [&str; 3] = ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"];

pub(crate) fn globals(h: &DisplayHandle) {
    h.create_global::<State, manager::WlDataDeviceManager, _>(3, ());
}
fn owner<R: Resource>(r: &R) -> Option<u64> {
    r.client()?
        .get_data::<ClientIdentity>()
        .map(|c| c.connection)
}
impl State {
    fn selection_focused(&self, connection: Option<u64>) -> bool {
        connection.is_some()
            && self
                .seat
                .focus
                .and_then(|id| self.surfaces.get(&id))
                .is_some_and(|surface| Some(surface.connection) == connection)
    }
    pub(crate) fn selection_focus_changed(&mut self) {
        self.selection.devices.retain(Resource::is_alive);
        let Some(handle) = self.selection.handle.as_ref() else {
            return;
        };
        for device in &self.selection.devices {
            if !self.selection_focused(owner(device)) {
                device.selection(None);
                continue;
            }
            let source = self.selection.source.as_ref().filter(|s| s.is_alive());
            if source.is_none() && self.selection.host.is_none() {
                device.selection(None);
                continue;
            }
            let Some(client) = device.client() else {
                continue;
            };
            let Ok(offer) = client.create_resource::<offer::WlDataOffer, _, Self>(
                handle,
                device.version(),
                OfferData {
                    source: source.cloned(),
                },
            ) else {
                continue;
            };
            device.data_offer(&offer);
            if let Some(data) = source.and_then(|s| s.data::<SourceData>()) {
                for mime in data.mimes.lock().unwrap_or_else(|p| p.into_inner()).iter() {
                    offer.offer(mime.clone());
                }
            } else {
                for mime in TEXT_MIMES {
                    offer.offer(mime.into());
                }
            }
            device.selection(Some(&offer));
        }
    }
    fn valid_offer(&self, resource: &offer::WlDataOffer, data: &OfferData) -> bool {
        data.source.as_ref().is_none_or(Resource::is_alive)
            && self.selection.source == data.source
            && self.selection_focused(owner(resource))
    }
    pub(crate) fn host_clipboard_changed(&mut self) {
        if let Some(host) = &self.selection.host {
            host.changed();
        }
        if let Some(old) = self.selection.source.take().filter(Resource::is_alive) {
            old.cancelled();
        }
        self.selection_focus_changed();
    }
    fn export_host_clipboard(&self) {
        let Some(host) = self.selection.host.as_ref() else {
            return;
        };
        let Some(source) = self.selection.source.as_ref() else {
            return;
        };
        let Some(data) = source.data::<SourceData>() else {
            return;
        };
        let mimes = data.mimes.lock().unwrap_or_else(|p| p.into_inner());
        let Some(mime) = TEXT_MIMES
            .iter()
            .find(|mime| mimes.iter().any(|m| m == **mime))
        else {
            return;
        };
        if let Ok((read, write)) = trames_shared::NativePipe::pair() {
            if host.write(read).is_ok() {
                source.send((*mime).into(), write.as_fd());
            }
        }
    }
}
impl GlobalDispatch<manager::WlDataDeviceManager, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<manager::WlDataDeviceManager>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(r, ());
    }
}
impl Dispatch<manager::WlDataDeviceManager, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        _: &manager::WlDataDeviceManager,
        request: manager::Request,
        _: &(),
        handle: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        match request {
            manager::Request::CreateDataSource { id } => {
                init.init(id, SourceData::default());
            }
            manager::Request::GetDataDevice { id, .. } => {
                let device = init.init(id, ());
                state.selection.handle = Some(handle.clone());
                state.selection.devices.push(device);
                state.selection_focus_changed();
            }
            _ => {}
        }
    }
}
impl Dispatch<source::WlDataSource, SourceData> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        r: &source::WlDataSource,
        request: source::Request,
        data: &SourceData,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        match request {
            source::Request::Offer { mime_type } => {
                let mut mimes = data.mimes.lock().unwrap_or_else(|p| p.into_inner());
                if mime_type.len() > 4096 || mimes.len() >= 128 {
                    r.post_error(1u32, "too many clipboard MIME types");
                } else if !mimes.contains(&mime_type) {
                    mimes.push(mime_type);
                }
            }
            source::Request::SetActions { dnd_actions } => {
                if matches!(dnd_actions, WEnum::Unknown(_)) {
                    r.post_error(0u32, "invalid data source actions");
                }
            }
            _ => {}
        }
    }
    fn destroyed(
        state: &mut Self,
        _: wayland_backend::server::ClientId,
        r: &source::WlDataSource,
        _: &SourceData,
    ) {
        if state.selection.source.as_ref() == Some(r) {
            state.selection.source = None;
            state.selection_focus_changed();
        }
    }
}
impl Dispatch<device::WlDataDevice, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &device::WlDataDevice,
        request: device::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        match request {
            device::Request::SetSelection { source, serial } => {
                if !state.selection_focused(owner(r))
                    || serial.wrapping_sub(state.serial) as i32 > 0
                    || source.as_ref().is_some_and(|s| owner(s) != owner(r))
                {
                    return;
                }
                if state.selection.source == source {
                    return;
                }
                if let Some(old) = state.selection.source.take().filter(Resource::is_alive) {
                    old.cancelled();
                }
                state.selection.source = source;
                state.selection_focus_changed();
                state.export_host_clipboard();
            }
            // No drag destination is exposed yet. Cancel the source cleanly;
            // don't pretend that a drag or host clipboard transfer succeeded.
            device::Request::StartDrag {
                source: Some(source),
                ..
            } => {
                source.cancelled();
            }
            _ => {}
        }
    }
}
impl Dispatch<offer::WlDataOffer, OfferData> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &offer::WlDataOffer,
        request: offer::Request,
        data: &OfferData,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if !state.valid_offer(r, data) {
            return;
        }
        match request {
            offer::Request::Accept { mime_type, .. } => {
                if let Some(source) = &data.source {
                    source.target(mime_type);
                }
            }
            offer::Request::Receive { mime_type, fd } => {
                if let Some(source) = &data.source {
                    let valid = source.data::<SourceData>().is_some_and(|d| {
                        d.mimes
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .contains(&mime_type)
                    });
                    if valid {
                        source.send(mime_type, fd.as_fd());
                    }
                } else if TEXT_MIMES.contains(&mime_type.as_str()) {
                    if let Some(host) = &state.selection.host {
                        let _ = host.read(fd);
                    }
                }
            }
            offer::Request::Finish => {
                r.post_error(
                    0u32,
                    "clipboard offers do not have drag-and-drop completion",
                );
            }
            _ => {}
        }
    }
}
