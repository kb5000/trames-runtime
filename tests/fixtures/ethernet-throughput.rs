// SPDX-License-Identifier: GPL-3.0-or-later
use std::{net::UdpSocket, time::Instant};
use trames_net::{Fabric, Network, NetworkMode};
fn bench(name: &str, size: usize, mut operation: impl FnMut()) {
    for _ in 0..64 {
        operation();
    }
    let mut samples = Vec::with_capacity(10000);
    let start = Instant::now();
    for _ in 0..10000 {
        let t = Instant::now();
        operation();
        samples.push(t.elapsed().as_nanos());
    }
    let elapsed = start.elapsed().as_secs_f64();
    samples.sort_unstable();
    println!(
        "{name},{size},{:.0},{:.2},{:.2}",
        10000.0 / elapsed,
        samples[5000] as f64 / 1000.0,
        samples[9900] as f64 / 1000.0
    );
}
fn main() {
    println!("path,bytes,packets_per_second,p50_us,p99_us");
    for size in [64, 1400] {
        let data = vec![0x5a; size];
        let mut buf = vec![0; size];
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.set_nonblocking(true).unwrap();
        rx.set_nonblocking(true).unwrap();
        let target = rx.local_addr().unwrap();
        bench("host_bsd_udp", size, || {
            assert_eq!(tx.send_to(&data, target).unwrap(), size);
            loop {
                match rx.recv(&mut buf) {
                    Ok(n) => {
                        assert_eq!(n, size);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now()
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let n = Network::new(NetworkMode::Full);
        let tx = n.socket(2, 2, 0).unwrap();
        let rx = n.socket(2, 2, 0).unwrap();
        rx.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = rx.local_addr().unwrap();
        bench("trames_native_udp", size, || {
            assert_eq!(tx.send(&data, 0, Some(target)).unwrap(), size);
            loop {
                match rx.recv(size, 0) {
                    Ok(r) => {
                        assert_eq!(r.data.len(), size);
                        break;
                    }
                    Err(trames_net::NetError(11)) => std::thread::yield_now(),
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let fabric = Fabric::new().unwrap();
        let a = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
        let b = Network::virtual_network(&fabric, 3, NetworkMode::Outbound).unwrap();
        let tx = a.socket(2, 2, 0).unwrap();
        let rx = b.socket(2, 2, 0).unwrap();
        rx.bind("10.0.0.3:34567".parse().unwrap()).unwrap();
        let target = rx.local_addr().unwrap();
        bench("trames_internal_ethernet_udp", size, || {
            assert_eq!(tx.send(&data, 0, Some(target)).unwrap(), size);
            loop {
                match rx.recv(size, 0) {
                    Ok(r) => {
                        assert_eq!(r.data.len(), size);
                        break;
                    }
                    Err(trames_net::NetError(11)) => std::thread::yield_now(),
                    Err(e) => panic!("{e}"),
                }
            }
        });
    }
}
