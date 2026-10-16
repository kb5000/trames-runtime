// SPDX-License-Identifier: GPL-3.0-or-later
//! Native, platform-independent Wayland compositor protocol and window state.
use std::{io, os::unix::net::UnixStream, sync::Arc};
use wayland_server::{backend::ClientData, Display, Resource};
mod gpu;
mod input;
mod scene;
pub use gpu::{GpuBudget, GpuImage, GpuPermit};
mod text;
pub use input::InputEvent;
pub use text::{TextContext, TextEdit};
mod server;
pub use server::{Server, Snapshot, SurfaceInfo};
mod protocol;
mod shell;
mod subsurface;
pub use scene::{BufferLease, ImageBuffer, ShmBuffer, SurfaceImage, WindowMode, WindowSnapshot};

/// Guest identity is attached by the VM bridge, never inferred from the host UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIdentity {
    pub connection: u64,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}
impl ClientData for ClientIdentity {}

pub struct Compositor {
    display: Display<State>,
    state: State,
}
struct State {
    next: u64,
    serial: u32,
    revision: u64,
    viewport: (u32, u32),
    seat: input::Seat,
    text: text::TextInputs,
    surfaces: std::collections::BTreeMap<u64, scene::Surface>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            next: 1,
            serial: 0,
            revision: 0,
            viewport: (1024, 768),
            seat: Default::default(),
            text: Default::default(),
            surfaces: Default::default(),
        }
    }
}
impl Compositor {
    pub fn new() -> io::Result<Self> {
        let display = Display::new().map_err(io::Error::other)?;
        State::globals(&display.handle());
        let mut state = State::default();
        state.initialize_input()?;
        Ok(Self { display, state })
    }
    pub fn windows(&self) -> Vec<WindowSnapshot> {
        scene::snapshot(&self.state.surfaces)
    }
    pub fn resize(&mut self, id: u64, width: u32, height: u32) -> bool {
        if width == 0 || height == 0 || width > 4096 || height > 4096 {
            return false;
        }
        let Some(surface) = self.state.surfaces.get_mut(&id) else {
            return false;
        };
        surface.requested_size = (width, height);
        if surface.mode == WindowMode::Floating {
            surface.restore_size = (width, height);
        }
        self.state.configure(id);
        self.state.changed();
        true
    }
    pub fn close(&mut self, id: u64) {
        if let Some(top) = self.state.surfaces.get(&id).and_then(|s| s.top.as_ref()) {
            top.close();
        }
    }
    pub fn set_mode(&mut self, id: u64, mode: WindowMode) {
        if let Some(s) = self.state.surfaces.get_mut(&id) {
            if mode == WindowMode::Maximized && s.mode == WindowMode::Floating {
                s.restore_size = s.size;
            }
            if mode == WindowMode::Floating && s.mode == WindowMode::Maximized {
                s.requested_size = s.restore_size;
            }
            if mode == WindowMode::Maximized {
                s.requested_size = self.state.viewport;
            }
            s.mode = mode;
            self.state.configure(id);
            self.state.changed();
        }
    }
    pub fn presented(&mut self, window: u64, revision: u64, milliseconds: u32) {
        let Some(root) = self.state.surfaces.get(&window) else {
            return;
        };
        if root.top.is_none() {
            return;
        }
        let mut visit = vec![window];
        let mut index = 0;
        while index < visit.len() {
            let Some(s) = self.state.surfaces.get_mut(&visit[index]) else {
                index += 1;
                continue;
            };
            visit.extend_from_slice(&s.children);
            if revision >= s.revision {
                s.gpu_presented = true;
            }
            while s
                .callbacks
                .front()
                .is_some_and(|(serial, _)| *serial <= revision)
            {
                for callback in s.callbacks.pop_front().unwrap().1 {
                    if callback.is_alive() {
                        callback.done(milliseconds);
                    }
                }
            }
            index += 1;
        }
    }
    pub fn connect(&mut self, stream: UnixStream, identity: ClientIdentity) -> io::Result<()> {
        self.display
            .handle()
            .insert_client(stream, Arc::new(identity))?;
        Ok(())
    }
    /// Nonblocking protocol progress. Native event-loop integration owns polling.
    pub fn dispatch(&mut self) -> io::Result<usize> {
        let count = self.display.dispatch_clients(&mut self.state)?;
        self.display.flush_clients()?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn standard_display_sync_replies_and_preserves_connection_identity() {
        let mut compositor = Compositor::new().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        compositor
            .connect(
                server,
                ClientIdentity {
                    connection: 42,
                    pid: 8,
                    uid: 1000,
                    gid: 1000,
                },
            )
            .unwrap();
        // wl_display.sync(new_id=2), encoded by the standard core wire ABI.
        client
            .write_all(
                &[
                    1u32.to_ne_bytes(),
                    (12u32 << 16).to_ne_bytes(),
                    2u32.to_ne_bytes(),
                ]
                .concat(),
            )
            .unwrap();
        assert_eq!(compositor.dispatch().unwrap(), 1);
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 24];
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 2);
        assert_eq!(
            u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
            12 << 16
        );
        assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
            (12 << 16) | 1
        );
        assert_eq!(u32::from_ne_bytes(bytes[20..24].try_into().unwrap()), 2);
    }
}
