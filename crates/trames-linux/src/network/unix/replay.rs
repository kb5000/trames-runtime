// SPDX-License-Identifier: GPL-3.0-or-later
//! At-most-once queue consumption and rights installation around ordered copies.
use super::*;
pub(super) struct Receive<R> {
    pub(super) received: Option<trames_vfs::LocalReceived<R>>,
    pub(super) rights: Option<(Vec<u32>, bool)>,
    pub(super) copies: crate::copy_replay::Replay,
    pub(super) finished: Option<Result<u64>>,
}
impl<R> Default for Receive<R> {
    fn default() -> Self {
        Self {
            received: None,
            rights: None,
            copies: Default::default(),
            finished: None,
        }
    }
}
pub(super) struct Io<'a, I: MessageIo> {
    pub(super) original: &'a mut I,
    pub(super) received: &'a mut Option<trames_vfs::LocalReceived<I::Rights>>,
    pub(super) rights: &'a mut Option<(Vec<u32>, bool)>,
    pub(super) sent: Option<&'a std::sync::OnceLock<Result<I::Rights>>>,
}
impl<I: MessageIo> MessageIo for Io<'_, I> {
    type Rights = I::Rights;
    fn kind(&self) -> u32 {
        self.original.kind()
    }
    fn connected(&self) -> bool {
        self.original.connected()
    }
    fn peer_address(&self) -> Vec<u8> {
        self.original.peer_address()
    }
    fn receive_address(&self, source: Vec<u8>, has_sender: bool) -> Vec<u8> {
        self.original.receive_address(source, has_sender)
    }
    fn pid_user_namespace(&self) -> &trames_vfs::UserNamespace {
        self.original.pid_user_namespace()
    }
    fn send_buffer(&self) -> usize {
        self.original.send_buffer()
    }
    fn nonblocking(&self) -> u32 {
        self.original.nonblocking()
    }
    fn recv(
        &mut self,
        count: usize,
        flags: u32,
    ) -> Option<Result<trames_vfs::LocalReceived<Self::Rights>>> {
        if self.received.is_none() {
            match self.original.recv(count, flags)? {
                Ok(received) => *self.received = Some(received),
                Err(error) => return Some(Err(error)),
            }
        }
        Some(Ok(self.received.as_ref().unwrap().clone()))
    }
    fn send(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: Self::Rights,
        identity: [u32; 3],
    ) -> Option<Result<usize>> {
        self.original
            .send(bytes, flags, destination, rights, identity)
    }
    fn send_explicit(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: Self::Rights,
        identity: [u32; 3],
    ) -> Option<Result<usize>> {
        self.original
            .send_explicit(bytes, flags, destination, rights, identity)
    }
    fn sender_credentials(&self) -> [u32; 3] {
        self.original.sender_credentials()
    }
    fn credentials(&self) -> &trames_vfs::Credentials {
        self.original.credentials()
    }
    fn local_pid(&self, global: u32) -> u32 {
        self.original.local_pid(global)
    }
    fn global_pid(&self, local: u32) -> Result<u32> {
        self.original.global_pid(local)
    }
    fn send_rights(&self, fds: &[u32]) -> Option<Result<Self::Rights>> {
        let Some(sent) = self.sent else {
            return self.original.send_rights(fds);
        };
        if let Some(rights) = sent.get() {
            return Some(rights.clone());
        }
        let rights = self.original.send_rights(fds)?;
        let _ = sent.set(rights.clone());
        Some(rights)
    }
    fn receive_rights(
        &mut self,
        rights: Self::Rights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool) {
        self.rights
            .get_or_insert_with(|| self.original.receive_rights(rights, capacity, cloexec))
            .clone()
    }
}
