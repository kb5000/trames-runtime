// SPDX-License-Identifier: GPL-3.0-or-later
//! Translate copied native ancillary metadata; no guest cmsg or pointer crosses
//! the host ABI. Aligned fixed-size storage and explicit family/length checks.
use super::*;
use nix::libc;
use std::{mem, os::fd::RawFd};
pub(super) fn enable(fd: RawFd, v6: bool, enabled: bool) -> Result<()> {
    let value = i32::from(enabled);
    let (level, kind) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    // SAFETY: live owned socket, a copied native integer of the exact ABI size.
    if unsafe { libc::setsockopt(fd, level, kind, (&value as *const i32).cast(), 4) } < 0 {
        return Err(from_io(io::Error::last_os_error()));
    }
    Ok(())
}
pub(super) fn receive(
    fd: RawFd,
    data: &mut [u8],
    peek: bool,
) -> Result<(usize, SocketAddr, Option<IpAddr>)> {
    // SAFETY: these are POD C structs; all pointer/size pairs below refer only
    // to live, bounded host storage and recvmsg initializes the returned prefix.
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut controls = [0usize; 32];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of_val(&address) as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controls.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&controls) as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, if peek { libc::MSG_PEEK } else { 0 }) };
    if n < 0 {
        return Err(from_io(io::Error::last_os_error()));
    }
    let source = match i32::from(address.ss_family) {
        libc::AF_INET if msg.msg_namelen as usize >= mem::size_of::<libc::sockaddr_in>() => {
            let a = unsafe {
                &*(&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
            };
            SocketAddr::new(
                Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(a.sin_port),
            )
        }
        libc::AF_INET6 if msg.msg_namelen as usize >= mem::size_of::<libc::sockaddr_in6>() => {
            let a = unsafe {
                &*(&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            SocketAddr::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr).into(),
                u16::from_be(a.sin6_port),
            )
        }
        _ => return Err(NetError(97)),
    };
    let mut destination = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !header.is_null() {
        let c = unsafe { &*header };
        if c.cmsg_level == libc::IPPROTO_IP
            && c.cmsg_type == libc::IP_PKTINFO
            && c.cmsg_len as usize
                >= unsafe { libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as _) } as usize
        {
            let info = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>())
            };
            destination = Some(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into());
        }
        if c.cmsg_level == libc::IPPROTO_IPV6
            && c.cmsg_type == libc::IPV6_PKTINFO
            && c.cmsg_len as usize
                >= unsafe { libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as _) } as usize
        {
            let info = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>())
            };
            destination = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr).into());
        }
        header = unsafe { libc::CMSG_NXTHDR(&msg, header) };
    }
    Ok((n as usize, source, destination))
}
pub(super) fn send(fd: RawFd, data: &[u8], peer: SocketAddr, source: IpAddr) -> Result<usize> {
    let address = SockAddr::from(peer);
    let mut controls = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = address.as_ptr().cast_mut().cast();
    msg.msg_namelen = address.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controls.as_mut_ptr().cast();
    let size = match source {
        IpAddr::V4(_) => mem::size_of::<libc::in_pktinfo>(),
        IpAddr::V6(_) => mem::size_of::<libc::in6_pktinfo>(),
    };
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(size as _) } as _;
    // SAFETY: aligned controls contains the checked cmsg header and complete
    // native pktinfo payload; address/data remain live for this nonblocking call.
    unsafe {
        let h = libc::CMSG_FIRSTHDR(&msg);
        (*h).cmsg_len = libc::CMSG_LEN(size as _) as _;
        match source {
            IpAddr::V4(ip) => {
                (*h).cmsg_level = libc::IPPROTO_IP;
                (*h).cmsg_type = libc::IP_PKTINFO;
                let mut info: libc::in_pktinfo = mem::zeroed();
                info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                std::ptr::write_unaligned(libc::CMSG_DATA(h).cast::<libc::in_pktinfo>(), info);
            }
            IpAddr::V6(ip) => {
                (*h).cmsg_level = libc::IPPROTO_IPV6;
                (*h).cmsg_type = libc::IPV6_PKTINFO;
                let mut info: libc::in6_pktinfo = mem::zeroed();
                info.ipi6_addr.s6_addr = ip.octets();
                std::ptr::write_unaligned(libc::CMSG_DATA(h).cast::<libc::in6_pktinfo>(), info);
            }
        }
    }
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 {
        Err(from_io(io::Error::last_os_error()))
    } else {
        Ok(n as usize)
    }
}
