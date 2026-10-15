// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only host address snapshot for the direct guest's logical eth0.
//! getifaddrs owns the list and sockaddr allocations until freeifaddrs. Nothing
//! from this list escapes as a pointer or changes host interface configuration.
use crate::NetworkInfo;
use nix::libc;
use std::{
    ffi::CStr,
    net::{Ipv4Addr, Ipv6Addr},
};

pub(crate) fn primary() -> Option<NetworkInfo> {
    let mut head = std::ptr::null_mut();
    // SAFETY: libc initializes head; a successful call owns a finite linked list.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let list = List(head);
    let mut entries = Vec::new();
    let mut current = list.0;
    while !current.is_null() {
        // SAFETY: each next/address/name belongs to the live getifaddrs list;
        // family selects the OS-defined sockaddr type and all values are copied.
        unsafe {
            let item = &*current;
            current = item.ifa_next;
            if item.ifa_addr.is_null()
                || item.ifa_netmask.is_null()
                || item.ifa_name.is_null()
                || item.ifa_flags & libc::IFF_UP as u32 == 0
                || item.ifa_flags & libc::IFF_LOOPBACK as u32 != 0
            {
                continue;
            }
            let name = CStr::from_ptr(item.ifa_name).to_bytes().to_vec();
            match (*item.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let a = &*item.ifa_addr.cast::<libc::sockaddr_in>();
                    let m = &*item.ifa_netmask.cast::<libc::sockaddr_in>();
                    let ip = Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes());
                    if !ip.is_unspecified() && !ip.is_loopback() {
                        entries.push((
                            name,
                            Some((ip, u32::from_be(m.sin_addr.s_addr).leading_ones() as u8)),
                            None,
                        ));
                    }
                }
                libc::AF_INET6 => {
                    let a = &*item.ifa_addr.cast::<libc::sockaddr_in6>();
                    let m = &*item.ifa_netmask.cast::<libc::sockaddr_in6>();
                    let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
                    // Scope IDs are not forwarded by the guest socket ABI.
                    if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_unicast_link_local() {
                        entries.push((
                            name,
                            None,
                            Some((
                                ip,
                                u128::from_be_bytes(m.sin6_addr.s6_addr).leading_ones() as u8,
                            )),
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    // Prefer the platform's ordinary interface; expose copied addresses under
    // the stable guest name eth0, not host interface indices or MAC addresses.
    let first = entries
        .iter()
        .filter(|e| e.1.is_some())
        .min_by_key(|e| usize::from(!matches!(e.0.as_slice(), b"en0" | b"eth0")))
        .or_else(|| entries.first())?;
    let mut info = NetworkInfo {
        id: 0,
        ipv4: Ipv4Addr::UNSPECIFIED,
        ipv6: Ipv6Addr::UNSPECIFIED,
        gateway4: Ipv4Addr::UNSPECIFIED,
        gateway6: Ipv6Addr::UNSPECIFIED,
        prefix4: 0,
        prefix6: 0,
        mtu: 1500,
    };
    for (name, v4, v6) in &entries {
        if *name != first.0 {
            continue;
        }
        if let Some((ip, prefix)) = v4 {
            info.ipv4 = *ip;
            info.prefix4 = *prefix;
        }
        if let Some((ip, prefix)) = v6 {
            info.ipv6 = *ip;
            info.prefix6 = *prefix;
        }
    }
    Some(info)
}
