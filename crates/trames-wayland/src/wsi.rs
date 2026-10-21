// SPDX-License-Identifier: GPL-3.0-or-later
//! Native WSI authentication survives transparent Wayland socket relays. The
//! shared inode is a retained capability, not a guest-selected connection ID.
use super::*;
use std::collections::BTreeMap;
use trames_shared::SharedFile;
use wayland_server::{Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New};

#[allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
#[allow(unused_imports, unused_unsafe, unused_variables, clippy::all)]
mod wire {
    use wayland_server;
    pub mod __interfaces {
        wayland_scanner::generate_interfaces!("native-wsi.xml");
    }
    use self::__interfaces::*;
    wayland_scanner::generate_server_code!("native-wsi.xml");
}
use wire::trames_native_wsi_v1::{Request, TramesNativeWsiV1};

struct Grant {
    connection: u64,
    object: u64,
    _file: SharedFile,
}
/// A published snapshot retains the inode too, so it cannot be recycled while
/// a coordinator still resolves an older snapshot during protocol teardown.
#[derive(Clone)]
pub struct WsiConnection {
    pub connection: u64,
    _file: SharedFile,
}
#[derive(Default)]
pub(crate) struct Grants(BTreeMap<(u64, u64), Grant>);
impl Grants {
    pub fn connections(&self) -> BTreeMap<(u64, u64), WsiConnection> {
        self.0
            .iter()
            .map(|(key, g)| {
                (
                    *key,
                    WsiConnection {
                        connection: g.connection,
                        _file: g._file.clone(),
                    },
                )
            })
            .collect()
    }
}
pub(crate) fn globals(handle: &DisplayHandle) {
    handle.create_global::<State, TramesNativeWsiV1, _>(1, ());
}
impl GlobalDispatch<TramesNativeWsiV1, ()> for State {
    fn bind(
        state: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        resource: New<TramesNativeWsiV1>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(resource, state.id());
    }
}
impl Dispatch<TramesNativeWsiV1, u64> for State {
    fn request(
        state: &mut Self,
        client: &Client,
        resource: &TramesNativeWsiV1,
        request: Request,
        object: &u64,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        let Request::Authenticate { file } = request else {
            return;
        };
        let Some(identity) = client.get_data::<ClientIdentity>() else {
            return;
        };
        if state.wsi.0.len() >= 64 || state.wsi.0.values().any(|g| g.object == *object) {
            resource.post_error(0u32, "native WSI capability limit");
            return;
        }
        let Ok(file) = SharedFile::import(file) else {
            resource.post_error(0u32, "native WSI requires a shared file");
            return;
        };
        if state.wsi.0.contains_key(&file.key()) {
            resource.post_error(0u32, "native WSI inode already granted");
            return;
        }
        state.wsi.0.insert(
            file.key(),
            Grant {
                connection: identity.connection,
                object: *object,
                _file: file,
            },
        );
        state.changed();
    }
    fn destroyed(
        state: &mut Self,
        _: wayland_backend::server::ClientId,
        _: &TramesNativeWsiV1,
        object: &u64,
    ) {
        state.wsi.0.retain(|_, g| g.object != *object);
        state.changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_shared::NativeSocket;

    fn message(id: u32, opcode: u32, words: &[u32]) -> Vec<u8> {
        [id, (((words.len() + 2) * 4) as u32) << 16 | opcode]
            .into_iter()
            .chain(words.iter().copied())
            .flat_map(u32::to_ne_bytes)
            .collect()
    }
    fn client(compositor: &mut Compositor, connection: u64) -> NativeSocket {
        let (client, server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        compositor
            .connect(
                server,
                ClientIdentity {
                    connection,
                    pid: 7,
                    uid: 0,
                    gid: 0,
                },
            )
            .unwrap();
        let socket = NativeSocket::from(client);
        socket.send_msg(&message(1, 1, &[2]), &[]).unwrap();
        compositor.dispatch().unwrap();
        let mut bytes = vec![0; 65536];
        let count = socket.rcv_msg(&mut bytes, &mut Default::default()).unwrap();
        bytes.truncate(count);
        let mut name = None;
        let mut cursor = 0;
        while cursor < bytes.len() {
            let size = (u32::from_ne_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) >> 16)
                as usize;
            let event = &bytes[cursor..cursor + size];
            if event.windows(21).any(|s| s == b"trames_native_wsi_v1\0") {
                name = Some(u32::from_ne_bytes(event[8..12].try_into().unwrap()));
            }
            cursor += size;
        }
        let mut arguments = vec![name.expect("advertised native WSI"), 21];
        let mut interface = b"trames_native_wsi_v1\0".to_vec();
        interface.resize(24, 0);
        arguments.extend(
            interface
                .chunks_exact(4)
                .map(|s| u32::from_ne_bytes(s.try_into().unwrap())),
        );
        arguments.extend([1, 3]);
        socket.send_msg(&message(2, 0, &arguments), &[]).unwrap();
        compositor.dispatch().unwrap();
        socket
    }
    fn authenticate(compositor: &mut Compositor, socket: &NativeSocket, file: &SharedFile) {
        let (fd, lease) = file.export().unwrap();
        socket.send_msg(&message(3, 1, &[]), &[fd]).unwrap();
        compositor.dispatch().unwrap();
        assert!(lease.claimed());
    }
    #[test]
    fn wsi_capability_follows_inode_and_expires_with_protocol_object() {
        let mut compositor = Compositor::new().unwrap();
        let socket = client(&mut compositor, 42);
        let file = SharedFile::anonymous().unwrap();
        authenticate(&mut compositor, &socket, &file);
        assert_eq!(
            compositor
                .state
                .wsi
                .connections()
                .get(&file.key())
                .map(|g| g.connection),
            Some(42)
        );
        let copy = SharedFile::anonymous().unwrap();
        assert!(!compositor.state.wsi.connections().contains_key(&copy.key()));
        socket.send_msg(&message(3, 0, &[]), &[]).unwrap();
        compositor.dispatch().unwrap();
        assert!(compositor.state.wsi.connections().is_empty());
    }
    #[test]
    fn wsi_other_connection_cannot_rebind_an_existing_capability() {
        let mut compositor = Compositor::new().unwrap();
        let first = client(&mut compositor, 42);
        let second = client(&mut compositor, 43);
        let file = SharedFile::anonymous().unwrap();
        authenticate(&mut compositor, &first, &file);
        authenticate(&mut compositor, &second, &file);
        assert_eq!(
            compositor
                .state
                .wsi
                .connections()
                .get(&file.key())
                .map(|g| g.connection),
            Some(42)
        );
        drop(first);
        compositor.dispatch().unwrap();
        assert!(compositor.state.wsi.connections().is_empty());
    }
}
