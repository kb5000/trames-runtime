// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux ABI acceptance across two independent internal-network guests.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, Instant},
};
fn main() {
    let mode = std::env::args().nth(1).unwrap();
    let size = 8 * 1024 * 1024usize;
    let block = vec![0x5a; 65536];
    let mut buf = vec![0u8; 65536];
    if mode == "server" {
        let listener = TcpListener::bind("0.0.0.0:34800").unwrap();
        let udp = UdpSocket::bind("0.0.0.0:34801").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        println!("READY");
        let (mut stream, _) = listener.accept().unwrap();
        let start = Instant::now();
        let mut total = 0;
        while total < size {
            let n = stream.read(&mut buf).unwrap();
            assert!(n != 0);
            assert!(buf[..n].iter().all(|b| *b == 0x5a));
            total += n;
        }
        stream.write_all(&(total as u64).to_le_bytes()).unwrap();
        println!(
            "TCP_RECEIVED bytes={total} seconds={:.6}",
            start.elapsed().as_secs_f64()
        );
        let (n, peer) = udp.recv_from(&mut buf).unwrap();
        assert_eq!(n, 60000);
        assert!(buf[..n].iter().all(|b| *b == 0x5a));
        udp.send_to(&buf[..n], peer).unwrap();
        println!("UDP_60000_OK");
    } else {
        let mut stream = TcpStream::connect("10.0.0.2:34800").unwrap();
        stream.set_nodelay(true).unwrap();
        let start = Instant::now();
        for _ in 0..size / block.len() {
            stream.write_all(&block).unwrap();
        }
        let mut ack = [0u8; 8];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(u64::from_le_bytes(ack), size as u64);
        println!(
            "TCP_SENT bytes={size} seconds={:.6}",
            start.elapsed().as_secs_f64()
        );
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        udp.connect("10.0.0.2:34801").unwrap();
        assert_eq!(udp.send(&block[..60000]).unwrap(), 60000);
        let n = udp.recv(&mut buf).unwrap();
        assert_eq!(n, 60000);
        assert!(buf[..n].iter().all(|b| *b == 0x5a));
        println!("UDP_60000_OK");
    }
}
