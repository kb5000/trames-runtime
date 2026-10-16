// SPDX-License-Identifier: MIT
// Adapted from wayland-backend 0.3.17 src/rs/socket.rs (MIT).
// Original copyright and license: vendor/wayland-backend/LICENSE.txt.
// Changes: Apple target coverage; safe FD borrowing; checked ancillary truncation.
use std::collections::VecDeque;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use std::mem::MaybeUninit;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use rustix::io::retry_on_intr;
use rustix::net::{
    recvmsg, send, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};

/// Maximum number of FD that can be sent in a single socket message
pub const MAX_FDS_OUT: usize = 28;
/// Maximum number of bytes that can be sent in a single socket message
pub const MAX_BYTES_OUT: usize = 4096;

/*
 * NativeSocket
 */

/// A wayland socket
#[derive(Debug)]
pub struct NativeSocket {
    stream: UnixStream,
}

impl NativeSocket {
    /// Send a single message to the socket
    ///
    /// A single socket message can contain several wayland messages
    ///
    /// The `fds` slice should not be longer than `MAX_FDS_OUT`, and the `bytes`
    /// slice should not be longer than `MAX_BYTES_OUT` otherwise the receiving
    /// end may lose some data.
    pub fn send_msg(&self, bytes: &[u8], fds: &[OwnedFd]) -> IoResult<usize> {
        #[cfg(not(any(target_vendor = "apple", target_os = "redox")))]
        let flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        #[cfg(any(target_vendor = "apple", target_os = "redox"))]
        let flags = SendFlags::DONTWAIT;

        if fds.len() > MAX_FDS_OUT || bytes.is_empty() && !fds.is_empty() {
            return Err(std::io::Error::from(ErrorKind::InvalidInput));
        }
        if !fds.is_empty() {
            let iov = [IoSlice::new(bytes)];
            let mut cmsg_space =
                vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
            let mut cmsg_buffer = SendAncillaryBuffer::new(&mut cmsg_space);
            let borrowed: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
            cmsg_buffer.push(SendAncillaryMessage::ScmRights(&borrowed));
            Ok(retry_on_intr(|| {
                sendmsg(self, &iov, &mut cmsg_buffer, flags)
            })?)
        } else {
            Ok(retry_on_intr(|| send(self, bytes, flags))?)
        }
    }

    /// Receive a single message from the socket
    ///
    /// Return the number of bytes received and the number of Fds received.
    ///
    /// Errors with `WouldBlock` is no message is available.
    ///
    /// A single socket message can contain several wayland messages.
    ///
    /// The `buffer` slice should be at least `MAX_BYTES_OUT` long and the `fds`
    /// slice `MAX_FDS_OUT` long, otherwise some data of the received message may
    /// be lost.
    pub fn rcv_msg(&self, buffer: &mut [u8], fds: &mut VecDeque<OwnedFd>) -> IoResult<usize> {
        #[cfg(not(any(target_vendor = "apple", target_os = "redox")))]
        let flags = RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC;
        #[cfg(any(target_vendor = "apple", target_os = "redox"))]
        let flags = RecvFlags::DONTWAIT;

        let mut cmsg_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_OUT))];
        let mut cmsg_buffer = RecvAncillaryBuffer::new(&mut cmsg_space);
        let mut iov = [IoSliceMut::new(buffer)];
        let msg = retry_on_intr(|| recvmsg(&self.stream, &mut iov[..], &mut cmsg_buffer, flags))?;

        if (msg.flags.bits() as i32) & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "truncated native ancillary message",
            ));
        }
        let received_fds = cmsg_buffer
            .drain()
            .filter_map(|cmsg| match cmsg {
                RecvAncillaryMessage::ScmRights(fds) => Some(fds),
                _ => None,
            })
            .flatten();
        fds.extend(received_fds);
        #[cfg(any(target_vendor = "apple", target_os = "redox"))]
        for fd in fds.iter() {
            if let Ok(flags) = rustix::io::fcntl_getfd(fd) {
                let _ = rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC);
            }
        }
        Ok(msg.bytes)
    }
}

impl From<UnixStream> for NativeSocket {
    fn from(stream: UnixStream) -> Self {
        // macOS doesn't have MSG_NOSIGNAL, but has SO_NOSIGPIPE instead
        #[cfg(target_vendor = "apple")]
        let _ = rustix::net::sockopt::set_socket_nosigpipe(&stream, true);
        Self { stream }
    }
}

impl AsFd for NativeSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

impl AsRawFd for NativeSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}
