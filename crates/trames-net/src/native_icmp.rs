// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest raw echo ABI over host unprivileged ICMP datagrams. No host raw socket.
use super::*;
use nix::libc;
use std::{
    mem::{size_of, size_of_val, zeroed},
    os::fd::AsRawFd,
};

#[derive(Default)]
pub(super) struct Echo {
    pub identifier: Option<[u8; 2]>,
    pub filter: [u32; 8],
    pub hop: Option<u8>,
    pub receive_hop: bool,
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
pub(super) fn configure(socket: &RawNativeSocket, family: u32) -> Result<()> {
    let option = if family == 2 {
        libc::IP_RECVTTL
    } else {
        libc::IPV6_RECVHOPLIMIT
    };
    let level = if family == 2 {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    };
    let enabled: libc::c_int = 1;
    // SAFETY: a live owned socket and an initialized integer of the native ABI.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as _,
        )
    };
    if result != 0 {
        return Err(from_io(io::Error::last_os_error()));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if family == 2 {
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as _,
            )
        };
        if result != 0 {
            return Err(from_io(io::Error::last_os_error()));
        }
    }
    Ok(())
}
impl Socket {
    pub(super) fn check_echo(&self, data: &[u8]) -> Result<[u8; 2]> {
        if !(8..=1400).contains(&data.len()) {
            return Err(NetError(90));
        }
        if data[0] != if self.family == 2 { 8 } else { 128 } || data[1] != 0 {
            return Err(NetError(95));
        }
        let id = [data[4], data[5]];
        if self
            .echo
            .borrow()
            .identifier
            .is_some_and(|previous| previous != id)
        {
            return Err(NetError(95));
        }
        Ok(id)
    }
    pub(super) fn recv_echo(&self, count: usize, flags: u32) -> Result<Received> {
        let mut data = vec![0u8; 65536];
        // SAFETY: sockaddr_storage/msghdr are C POD structures; all pointers below
        // refer to initialized, writable host-owned buffers for this call only.
        let mut source: libc::sockaddr_storage = unsafe { zeroed() };
        let mut control = [0usize; 64];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control) as _;
        let length = unsafe {
            libc::recvmsg(
                self.native.as_fd().as_raw_fd(),
                &mut msg,
                if flags & MSG_PEEK != 0 {
                    libc::MSG_PEEK
                } else {
                    0
                },
            )
        };
        if length < 0 {
            return Err(from_io(io::Error::last_os_error()));
        }
        data.truncate(length as usize);
        let address = unsafe {
            match source.ss_family as i32 {
                libc::AF_INET if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in>() => {
                    let a =
                        &*(&source as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                    SocketAddr::new(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(), 0)
                }
                libc::AF_INET6 if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in6>() => {
                    let a =
                        &*(&source as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                    SocketAddr::new(Ipv6Addr::from(a.sin6_addr.s6_addr).into(), 0)
                }
                _ => return Err(NetError(5)),
            }
        };
        let mut hop = None;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut destination = Ipv4Addr::UNSPECIFIED;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let destination = Ipv4Addr::UNSPECIFIED;
        // Kernel-produced ancillary records are bounded again before decoding.
        // CMSG_* performs the platform's alignment (Darwin differs from Linux).
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            let end = control.as_ptr() as usize
                + (msg.msg_controllen as usize).min(size_of_val(&control));
            while !c.is_null() && (c as usize) + size_of::<libc::cmsghdr>() <= end {
                let header = &*c;
                let bytes = libc::CMSG_DATA(c);
                if (header.cmsg_len as usize) < libc::CMSG_LEN(0) as usize
                    || c as usize + header.cmsg_len as usize > end
                {
                    break;
                }
                let size = header.cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                if header.cmsg_level == libc::IPPROTO_IP
                    && matches!(header.cmsg_type, libc::IP_TTL | libc::IP_RECVTTL)
                    || header.cmsg_level == libc::IPPROTO_IPV6
                        && header.cmsg_type == libc::IPV6_HOPLIMIT
                {
                    hop = if size >= size_of::<libc::c_int>() {
                        u8::try_from(bytes.cast::<libc::c_int>().read_unaligned()).ok()
                    } else if size == 1 {
                        Some(*bytes)
                    } else {
                        None
                    };
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if header.cmsg_level == libc::IPPROTO_IP
                    && header.cmsg_type == libc::IP_PKTINFO
                    && size >= size_of::<libc::in_pktinfo>()
                {
                    destination = Ipv4Addr::from(
                        bytes
                            .cast::<libc::in_pktinfo>()
                            .read_unaligned()
                            .ipi_addr
                            .s_addr
                            .to_ne_bytes(),
                    );
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        let header = if self.family == 2 && data.first().is_some_and(|v| v >> 4 == 4) {
            let offset = (data[0] & 15) as usize * 4;
            if offset < 20 || data.len() < offset + 8 {
                return Err(NetError(5));
            }
            hop = Some(data[8]);
            offset
        } else {
            0
        };
        if data.len() < header + 8 || data[header] != if self.family == 2 { 0 } else { 129 } {
            self.discard_peeked_echo(flags);
            return Err(NetError(11));
        }
        let mut echo = self.echo.borrow_mut();
        if echo.identifier.is_none()
            || (self.family == 10 && echo.filter[129 / 32] & (1 << (129 % 32)) != 0)
        {
            self.discard_peeked_echo(flags);
            return Err(NetError(11));
        }
        let id = echo.identifier.expect("checked echo identifier");
        let old_id = u16::from_be_bytes(data[header + 4..header + 6].try_into().unwrap());
        let old_checksum = u16::from_be_bytes(data[header + 2..header + 4].try_into().unwrap());
        data[header + 4..header + 6].copy_from_slice(&id);
        if self.family == 2 {
            data[header + 2..header + 4].fill(0);
            let check = checksum(&data[header..]);
            data[header + 2..header + 4].copy_from_slice(&check.to_be_bytes());
            if header == 0 {
                // Linux ping sockets omit the IPv4 header. Restore the guest raw
                // ABI using received TTL, destination pktinfo and source sockaddr.
                let ttl = hop.ok_or(NetError(5))?;
                let mut ip = vec![0u8; 20];
                ip[0] = 0x45;
                ip[8] = ttl;
                ip[9] = 1;
                ip[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
                if let IpAddr::V4(source) = address.ip() {
                    ip[12..16].copy_from_slice(&source.octets());
                }
                ip[16..20].copy_from_slice(&destination.octets());
                let check = checksum(&ip);
                ip[10..12].copy_from_slice(&check.to_be_bytes());
                ip.extend(data);
                data = ip;
            }
        } else {
            // Preserve the host-validated IPv6 checksum after restoring the ID
            // with RFC 1624 one's-complement incremental adjustment.
            // The full IPv6 pseudo-header never crosses into the guest ABI.
            let mut sum = (!old_checksum as u32) + (!old_id as u32) + u16::from_be_bytes(id) as u32;
            while sum >> 16 != 0 {
                sum = (sum & 65535) + (sum >> 16);
            }
            data[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        }
        echo.hop = hop;
        let length = data.len();
        data.truncate(count);
        Ok(Received {
            data,
            address: Some(address),
            length,
            truncated: length > count,
        })
    }
    fn discard_peeked_echo(&self, flags: u32) {
        if flags & MSG_PEEK != 0 {
            // A rejected packet must not stay at the front of the host queue.
            // This socket is scheduler-owned; no concurrent reader can consume
            // a different packet between the peek and this nonblocking discard.
            let mut byte = 0u8;
            unsafe {
                libc::recv(
                    self.native.as_fd().as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    0,
                );
            }
        }
    }
}
