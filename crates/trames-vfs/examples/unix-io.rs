// SPDX-License-Identifier: GPL-3.0-or-later
//! Original Unix shared-resource hot paths, excluding guest boot and teardown.
//! Run the same example against both runtime revisions, alternate processes and
//! compare repeated release samples after all conformance workers have stopped.
use std::hint::black_box;
use std::time::Instant;
use trames_vfs::Vfs;

fn main() {
    let repetitions: usize = std::env::args()
        .nth(1)
        .map_or(200_000, |n| n.parse().unwrap());
    assert!(repetitions > 0);
    for (name, kind, size, message) in [
        ("stream-64", 1, 64, false),
        ("stream-4096", 1, 4096, false),
        ("dgram-64", 2, 64, false),
        ("dgram-4096", 2, 4096, false),
        ("seqpacket-64", 5, 64, false),
        ("recvmsg-stream-64", 1, 64, true),
    ] {
        let mut vfs = Vfs::default();
        let [tx, rx] = vfs.socketpair(1, kind, 0).unwrap();
        let fds = vfs.direct_descriptors();
        let tx = fds.get(tx).unwrap();
        let rx = fds.get(rx).unwrap();
        let payload = vec![0x5a; size];
        let start = Instant::now();
        for _ in 0..repetitions {
            assert_eq!(tx.write(black_box(&payload)).unwrap(), size);
            let bytes = if message {
                rx.recv_local_message(size, 0).unwrap().unwrap().data
            } else {
                rx.read(size).unwrap()
            };
            assert_eq!(black_box(&bytes).len(), size);
        }
        println!(
            "{name}\t{:.3}",
            start.elapsed().as_nanos() as f64 / repetitions as f64
        );
        black_box(vfs);
    }
    let mut vfs = Vfs::default();
    let [a, _b] = vfs.socketpair(1, 1, 0).unwrap();
    let fd = vfs.direct_descriptors().get(a).unwrap();
    let start = Instant::now();
    for _ in 0..repetitions * 8 {
        black_box(fd.poll_ready(black_box(0x2005)).unwrap());
    }
    println!(
        "poll-empty\t{:.3}",
        start.elapsed().as_nanos() as f64 / (repetitions * 8) as f64
    );
    black_box(vfs);
}
