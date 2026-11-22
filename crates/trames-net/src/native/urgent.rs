// SPDX-License-Identifier: GPL-3.0-or-later
//! XNU consumes an urgent byte even for MSG_PEEK when the cursor is at the mark.
//! Preserve that byte and its position on the endpoint until a normal read advances.
use super::*;

#[derive(Default)]
pub(super) struct Cursor {
    byte: Option<u8>,
    consumed: bool,
}
impl Cursor {
    pub(super) fn marked(&self) -> bool {
        self.byte.is_some()
    }
    pub(super) fn pending(&self) -> bool {
        self.marked() && !self.consumed
    }
    pub(super) fn read(
        &mut self,
        endpoint: &Endpoint,
        socket: &TcpStream,
        dst: &mut [u8],
        flags: u32,
    ) -> Result<usize> {
        if self.marked() && endpoint.native_urgent_pending()? {
            // A newer wire indication supersedes the previous byte.
            self.byte = None;
        }
        let peek = flags & MSG_PEEK != 0;
        if flags & MSG_OOB != 0 {
            if endpoint.control().out_of_band_inline().map_err(from_io)? {
                return Err(NetError(22));
            }
            if let Some(byte) = self.byte {
                if self.consumed {
                    return Err(NetError(22));
                }
                self.consumed = !peek;
                if let Some(first) = dst.first_mut() {
                    *first = byte;
                    return Ok(1);
                }
                return Ok(0);
            }
            let at_mark = endpoint.host_at_mark()?;
            let n = direct::host_read(socket, dst, flags)?;
            if at_mark && n != 0 {
                self.byte = Some(dst[0]);
                self.consumed = !peek;
            }
            return Ok(n);
        }
        if let Some(byte) = self.byte {
            if !dst.is_empty() {
                if endpoint.control().out_of_band_inline().map_err(from_io)? && !self.consumed {
                    dst[0] = byte;
                    if !peek {
                        self.byte = None;
                    }
                    return Ok(1);
                }
                if !peek {
                    self.byte = None;
                }
            }
        }
        direct::host_read(socket, dst, flags)
    }
}
impl Endpoint {
    pub(super) fn native_urgent_pending(&self) -> Result<bool> {
        let queue = self.urgent_fd().map_err(from_io)?;
        // SAFETY: kevent fills one record, with no changes and a live queue.
        let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let n = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &timeout,
            )
        };
        if n < 0 {
            return Err(from_io(io::Error::last_os_error()));
        }
        // EOF alone is not an urgent indication.
        Ok(n == 1 && unsafe { event.assume_init() }.fflags & libc::NOTE_OOB != 0)
    }
}
