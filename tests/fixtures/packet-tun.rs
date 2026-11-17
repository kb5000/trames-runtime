// SPDX-License-Identifier: GPL-3.0-or-later
//! Standalone Linux ABI smoke test; build with the installed Rust musl target.
use std::{
    ffi::c_void,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
unsafe extern "C" {
    fn open(path: *const u8, flags: i32, ...) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const c_void, len: u32) -> i32;
    fn read(fd: i32, buf: *mut c_void, len: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, len: usize) -> isize;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(fd: i32, operation: i32, target: i32, event: *const u8) -> i32;
    fn epoll_wait(fd: i32, event: *mut u8, max: i32, timeout: i32) -> i32;
}
#[track_caller]
fn ok(n: i32) -> i32 {
    assert!(n >= 0, "{}", std::io::Error::last_os_error());
    n
}
fn fd(n: i32) -> OwnedFd {
    unsafe { OwnedFd::from_raw_fd(ok(n)) }
}
#[track_caller]
fn request(control: i32, code: u64, bytes: &mut [u8; 40]) {
    ok(unsafe { ioctl(control, code, bytes.as_mut_ptr()) });
}
fn main() {
    let tun = fd(unsafe { open(c"/dev/net/tun".as_ptr().cast(), 2 | 0x800) });
    let mut ifreq = [0u8; 40];
    ifreq[..5].copy_from_slice(b"tun%d");
    ifreq[16..18].copy_from_slice(&0x1001u16.to_le_bytes());
    request(tun.as_raw_fd(), 0x400454ca, &mut ifreq);
    assert_eq!(&ifreq[..5], b"tun0\0");
    let control = fd(unsafe { socket(2, 2, 0) });
    let mut config = [0u8; 40];
    config[..4].copy_from_slice(b"tun0");
    config[16..18].copy_from_slice(&2u16.to_le_bytes());
    config[20..24].copy_from_slice(&[192, 0, 2, 1]);
    request(control.as_raw_fd(), 0x8916, &mut config);
    config[20..24].copy_from_slice(&[255, 255, 255, 0]);
    request(control.as_raw_fd(), 0x891c, &mut config);
    config[16..18].copy_from_slice(&0x91u16.to_le_bytes());
    request(control.as_raw_fd(), 0x8914, &mut config);
    request(control.as_raw_fd(), 0x8933, &mut config);
    let index = i32::from_le_bytes(config[16..20].try_into().unwrap());
    assert!(index > 0);
    let tap = fd(unsafe { socket(17, 3, 0x0300) });
    let mut ll = [0u8; 20];
    ll[..2].copy_from_slice(&17u16.to_le_bytes());
    ll[2..4].copy_from_slice(&3u16.to_be_bytes());
    ll[4..8].copy_from_slice(&index.to_le_bytes());
    ok(unsafe { bind(tap.as_raw_fd(), ll.as_ptr(), 20) });
    let instructions = [6u16.to_le_bytes()[0], 0, 0, 0, 0xff, 0xff, 0, 0];
    let mut fprog = [0u8; 16];
    fprog[0] = 1;
    fprog[8..16].copy_from_slice(&(instructions.as_ptr() as u64).to_le_bytes());
    ok(unsafe { setsockopt(tap.as_raw_fd(), 1, 26, fprog.as_ptr().cast(), 16) });
    let epoll = fd(unsafe { epoll_create1(0) });
    let mut event = [0u8; 16];
    event[..4].copy_from_slice(&1u32.to_le_bytes());
    ok(unsafe { epoll_ctl(epoll.as_raw_fd(), 1, tun.as_raw_fd(), event.as_ptr()) });
    let udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 7001)).unwrap();
    udp.set_nonblocking(true).unwrap();
    let sender = udp.try_clone().unwrap();
    let sending = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        sender
            .send_to(
                b"tun ABI",
                SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7002),
            )
            .unwrap();
    });
    assert_eq!(
        unsafe { epoll_wait(epoll.as_raw_fd(), event.as_mut_ptr(), 1, 1000) },
        1
    );
    sending.join().unwrap();
    let mut packet = [0u8; 2048];
    let n = unsafe { read(tun.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len()) };
    assert!(n >= 28);
    let n = n as usize;
    assert_eq!(&packet[28..n], b"tun ABI");
    let mut captured = [0u8; 2048];
    assert_eq!(
        unsafe {
            read(
                tap.as_raw_fd(),
                captured.as_mut_ptr().cast(),
                captured.len(),
            )
        },
        n as isize
    );
    assert_eq!(&captured[..n], &packet[..n]);
    for i in 0..4 {
        packet.swap(12 + i, 16 + i);
    }
    packet.swap(20, 22);
    packet.swap(21, 23);
    packet[26..28].fill(0); // IPv4 UDP checksum may be zero; IP checksum is unchanged by swapping addresses.
    assert_eq!(
        unsafe { write(tun.as_raw_fd(), packet.as_ptr().cast(), n) },
        n as isize
    );
    let mut reply = [0u8; 100];
    assert_eq!(udp.recv(&mut reply).unwrap(), 7);
    assert_eq!(&reply[..7], b"tun ABI");
    drop(tun);
    ethernet();
    println!("packet-tun: Linux ioctl, socket BPF, epoll, TUN and UDP round trip passed");
}

fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    bytes.extend_from_slice(&((value.len() + 4) as u16).to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(value);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}
fn nl(control: i32, kind: u16, flags: u16, data: &[u8]) {
    let mut bytes = ((16 + data.len()) as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&(flags | 5).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(data);
    assert_eq!(
        unsafe { write(control, bytes.as_ptr().cast(), bytes.len()) },
        bytes.len() as isize
    );
    let mut reply = [0u8; 8192];
    let n = unsafe { read(control, reply.as_mut_ptr().cast(), reply.len()) };
    assert!(
        n >= 20,
        "netlink reply: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&reply[4..6], &2u16.to_le_bytes());
    assert_eq!(&reply[16..20], &0i32.to_le_bytes());
}
fn ethernet() {
    let control = fd(unsafe { socket(16, 3, 0) });
    let ioctl_fd = fd(unsafe { socket(2, 2, 0) });
    let mut bridge = vec![0u8; 16];
    bridge[8] = 1;
    bridge[12] = 1;
    attribute(&mut bridge, 3, b"abi-br\0");
    let mut info = vec![];
    attribute(&mut info, 1, b"bridge\0");
    let mut opts = vec![];
    attribute(&mut opts, 7, &[1]);
    attribute(&mut info, 2 | 0x8000, &opts);
    attribute(&mut bridge, 18 | 0x8000, &info);
    nl(control.as_raw_fd(), 16, 0x600, &bridge);
    let mut config = [0u8; 40];
    config[..6].copy_from_slice(b"abi-br");
    request(ioctl_fd.as_raw_fd(), 0x8933, &mut config);
    let br = u32::from_le_bytes(config[16..20].try_into().unwrap());
    let mut taps = vec![];
    for name in [b"abi-tap0", b"abi-tap1"] {
        let tap = fd(unsafe { open(c"/dev/net/tun".as_ptr().cast(), 2 | 0x800) });
        let mut config = [0u8; 40];
        config[..name.len()].copy_from_slice(name);
        config[16..18].copy_from_slice(&0x1002u16.to_le_bytes());
        request(tap.as_raw_fd(), 0x400454ca, &mut config);
        request(ioctl_fd.as_raw_fd(), 0x8933, &mut config);
        let index = u32::from_le_bytes(config[16..20].try_into().unwrap());
        let mut link = vec![0u8; 16];
        link[4..8].copy_from_slice(&index.to_le_bytes());
        link[8] = 1;
        link[12] = 1;
        attribute(&mut link, 10, &br.to_le_bytes());
        nl(control.as_raw_fd(), 16, 0, &link);
        let mut link = link[..16].to_vec();
        link[0] = 7;
        link[8..16].fill(0);
        let mut vlans = vec![];
        attribute(&mut vlans, 2, &[6, 0, 10, 0]);
        attribute(&mut link, 26 | 0x8000, &vlans);
        nl(control.as_raw_fd(), 19, 0, &link);
        taps.push(tap);
    }
    let wire = [
        &[2, 55, 44, 33, 22, 11, 2, 11, 22, 33, 44, 55, 0x88, 0xb5][..],
        b"Linux Ethernet ABI",
    ]
    .concat();
    assert_eq!(
        unsafe { write(taps[0].as_raw_fd(), wire.as_ptr().cast(), wire.len()) },
        wire.len() as isize
    );
    let mut received = [0u8; 2048];
    let n = unsafe {
        read(
            taps[1].as_raw_fd(),
            received.as_mut_ptr().cast(),
            received.len(),
        )
    };
    assert_eq!(n, wire.len() as isize);
    assert_eq!(&received[..n as usize], wire);
    println!("ethernet: TAP, Linux bridge/VLAN controls and opaque frame forwarding passed");
}
