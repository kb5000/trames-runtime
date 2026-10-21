// SPDX-License-Identifier: GPL-3.0-or-later
//! Native, platform-independent Wayland compositor protocol and window state.
use std::{io, os::unix::net::UnixStream, sync::Arc};
use wayland_server::{backend::ClientData, Display, Resource};
mod frame;
mod gpu;
mod input;
mod selection;
mod wsi;
pub use selection::HostClipboard;
pub use wsi::WsiConnection;
mod scene;
pub use gpu::{GpuBudget, GpuImage, GpuPermit};
mod text;
pub use input::InputEvent;
pub use text::{TextContext, TextEdit};
mod server;
pub use server::{Server, Snapshot, SurfaceInfo};
mod popup;
mod protocol;
mod shell;
mod subsurface;
mod xwayland;
mod xwm;
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
    clients: std::collections::BTreeMap<u64, wayland_server::Client>,
    exports: Vec<(u64, trames_shared::ExportLease)>,
    callback_timeout: Option<std::time::Duration>,
}
struct State {
    next: u64,
    serial: u32,
    revision: u64,
    viewport: (u32, u32),
    seat: input::Seat,
    selection: selection::Selection,
    text: text::TextInputs,
    xwayland: xwayland::Xwayland,
    wsi: wsi::Grants,
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
            selection: Default::default(),
            text: Default::default(),
            xwayland: Default::default(),
            wsi: Default::default(),
            surfaces: Default::default(),
        }
    }
}
impl Compositor {
    pub fn new() -> io::Result<Self> {
        let display = Display::new().map_err(io::Error::other)?;
        let mut state = State::default();
        State::globals(&display.handle(), state.xwayland.authorized.clone());
        state.initialize_input()?;
        Ok(Self {
            display,
            state,
            clients: Default::default(),
            exports: Vec::new(),
            callback_timeout: None,
        })
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
        self.state.xcommand(id, xwm::Command::Close);
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
        if mode == WindowMode::Minimized
            && self
                .state
                .seat
                .focus
                .is_some_and(|focused| self.state.is_descendant(focused, id))
        {
            self.state.input(InputEvent::Focus { window: None });
        }
    }
    pub fn presented(&mut self, window: u64, revision: u64, milliseconds: u32) {
        let now = std::time::Instant::now();
        let Some(root) = self.state.surfaces.get(&window) else {
            return;
        };
        if !root.is_toplevel() {
            return;
        }
        let mut visit = vec![window];
        let mut index = 0;
        while index < visit.len() {
            let Some(s) = self.state.surfaces.get_mut(&visit[index]) else {
                index += 1;
                continue;
            };
            // An unmapped subtree was absent from the displayed scene. In
            // particular, a parent's SHM frame cannot acknowledge a child's
            // first GPU frame before that child has attached any image.
            if s.dismissed || s.current.is_none() {
                index += 1;
                continue;
            }
            visit.extend_from_slice(&s.children);
            if revision >= s.revision {
                s.gpu_presented = true;
            }
            s.callback_pacer.presented(revision, milliseconds, now);
            index += 1;
        }
    }
    fn flush_callbacks(&mut self) -> Option<std::time::Duration> {
        let now = std::time::Instant::now();
        self.state
            .surfaces
            .values_mut()
            .filter_map(|s| s.flush_callbacks(now))
            .min()
    }
    pub fn connect(&mut self, stream: UnixStream, identity: ClientIdentity) -> io::Result<()> {
        let client = self
            .display
            .handle()
            .insert_client(stream, Arc::new(identity))?;
        self.clients.insert(identity.connection, client);
        Ok(())
    }
    pub(crate) fn retain_exports(
        &mut self,
        connection: u64,
        leases: Vec<trames_shared::ExportLease>,
    ) {
        if self.clients.contains_key(&connection) {
            self.exports
                .extend(leases.into_iter().map(|lease| (connection, lease)));
        }
    }
    /// Nonblocking protocol progress. Native event-loop integration owns polling.
    pub fn dispatch(&mut self) -> io::Result<usize> {
        self.state.pump_xwm();
        let count = self.display.dispatch_clients(&mut self.state)?;
        self.callback_timeout = self.flush_callbacks();
        self.display.flush_clients()?;
        let handle = self.display.handle().backend_handle();
        self.clients
            .retain(|_, client| handle.get_client_data(client.id()).is_ok());
        self.exports.retain(|(connection, lease)| {
            self.clients.contains_key(connection) && !lease.claimed()
        });
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn parent_presentation_does_not_signal_unmapped_subsurface_callbacks() {
        fn message(id: u32, opcode: u32, words: &[u32]) -> Vec<u8> {
            [id, (((words.len() + 2) * 4) as u32) << 16 | opcode]
                .into_iter()
                .chain(words.iter().copied())
                .flat_map(u32::to_ne_bytes)
                .collect()
        }
        fn replies(client: &mut UnixStream) -> Vec<u32> {
            let mut bytes = [0; 4096];
            let n = match client.read(&mut bytes) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                Err(e) => panic!("callback read: {e}"),
            };
            let mut callbacks = Vec::new();
            let mut cursor = 0;
            while cursor < n {
                let id = u32::from_ne_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                let header = u32::from_ne_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                if (9..15).contains(&id) && header & 0xffff == 0 {
                    callbacks.push(id);
                }
                cursor += (header >> 16) as usize;
            }
            callbacks.sort();
            callbacks
        }
        struct Image;
        // SAFETY: this protocol-only image owns no native resource or pointer.
        unsafe impl GpuImage for Image {
            fn dimensions(&self) -> (u32, u32) {
                (16, 16)
            }
            fn metal_texture(&self) -> usize {
                0
            }
            fn ready(&self) -> io::Result<bool> {
                Ok(true)
            }
        }
        let mut compositor = Compositor::new().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        compositor
            .connect(
                server,
                ClientIdentity {
                    connection: 42,
                    pid: 7,
                    uid: 0,
                    gid: 0,
                },
            )
            .unwrap();
        client.write_all(&message(1, 1, &[2])).unwrap();
        compositor.dispatch().unwrap();
        replies(&mut client);
        let mut bind = vec![1, 14]; // the advertised core compositor global
        bind.extend(
            b"wl_compositor\0\0\0"
                .chunks_exact(4)
                .map(|s| u32::from_ne_bytes(s.try_into().unwrap())),
        );
        bind.extend([4, 3]);
        client.write_all(&message(2, 0, &bind)).unwrap();
        for id in 4..9 {
            client.write_all(&message(3, 0, &[id])).unwrap();
        }
        for id in 4..9 {
            client.write_all(&message(id, 3, &[id + 5])).unwrap();
            client.write_all(&message(id, 6, &[])).unwrap();
        }
        for _ in 0..20 {
            compositor.dispatch().unwrap();
        }
        let ids: Vec<_> = (4..9)
            .map(|id| {
                *compositor
                    .state
                    .surfaces
                    .iter()
                    .find(|(_, s)| s.resource.id().protocol_id() == id)
                    .unwrap()
                    .0
            })
            .collect();
        let [root, empty, nested, visible, dismissed]: [u64; 5] = ids.try_into().unwrap();
        for id in [root, nested, visible, dismissed] {
            compositor.state.surfaces.get_mut(&id).unwrap().current =
                Some(ImageBuffer::Gpu(Arc::new(Image)));
        }
        compositor.state.surfaces.get_mut(&root).unwrap().x11 = Some(((1, 0, 0), 1));
        compositor.state.surfaces.get_mut(&root).unwrap().children =
            vec![empty, visible, dismissed];
        compositor.state.surfaces.get_mut(&empty).unwrap().children = vec![nested];
        for (id, parent) in [
            (empty, root),
            (nested, empty),
            (visible, root),
            (dismissed, root),
        ] {
            compositor.state.surfaces.get_mut(&id).unwrap().parent = Some((parent, 0, 0));
        }
        compositor
            .state
            .surfaces
            .get_mut(&dismissed)
            .unwrap()
            .dismissed = true;
        // A displayed parent is not evidence that a bufferless child, or its
        // descendants, was displayed. Firefox uses this distinction to stop
        // its initial-frame fallback timer only after the first real buffer.
        compositor.presented(root, compositor.state.revision, 1000);
        compositor.dispatch().unwrap();
        assert_eq!(replies(&mut client), vec![9, 12]);
        assert_eq!(
            compositor.windows()[0]
                .scene
                .iter()
                .map(|i| i.surface)
                .collect::<Vec<_>>(),
            vec![root, visible]
        );

        compositor.state.surfaces.get_mut(&empty).unwrap().current =
            Some(ImageBuffer::Gpu(Arc::new(Image)));
        compositor.presented(root, compositor.state.revision, 1020);
        compositor.dispatch().unwrap();
        assert_eq!(replies(&mut client), vec![10, 11]);

        let revision = compositor.state.revision;
        client.write_all(&message(4, 3, &[14])).unwrap();
        client.write_all(&message(4, 6, &[])).unwrap();
        for _ in 0..4 {
            compositor.dispatch().unwrap();
        }
        assert_eq!(compositor.state.revision, revision);
        std::thread::sleep(std::time::Duration::from_millis(20));
        compositor.dispatch().unwrap();
        assert_eq!(replies(&mut client), vec![14]);
        // A client may update the same buffer in place: explicit damage still
        // publishes new content even without another attach request.
        client.write_all(&message(4, 2, &[0, 0, 16, 16])).unwrap();
        client.write_all(&message(4, 6, &[])).unwrap();
        for _ in 0..4 {
            compositor.dispatch().unwrap();
        }
        assert!(compositor.state.revision > revision);
    }
    #[test]
    fn disconnected_clients_cancel_unconsumed_shared_fd_transfers() {
        let server = Server::new().unwrap();
        let (connection, socket) = server.connect(1, 0, 0).unwrap();
        let budget = trames_shared::SharedBudget::new(65536);
        let file = trames_shared::SharedFile::anonymous_in(budget.clone()).unwrap();
        file.set_len(65536).unwrap();
        file.reserve_range(0, 65536).unwrap();
        let (fd, lease) = file.export().unwrap();
        drop(file);
        drop(fd);
        server.retain_exports(connection, vec![lease]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert_eq!(budget.available(), 0);
        drop(socket);
        let began = std::time::Instant::now();
        while budget.available() != 65536 {
            assert!(began.elapsed() < std::time::Duration::from_secs(2));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
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
