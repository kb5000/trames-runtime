// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared-VM immutable reads, plus a disjoint-RW control of the guarded fallback.
use std::{
    hint::black_box,
    sync::{Arc, Barrier},
    time::Instant,
};
use trames_memory::{
    parallel::{Registry, View},
    CpuMemory, Memory, NativeMemory, Permissions,
};
const BASE: u64 = 0x40000;
const READ: u64 = 65536;

fn sample(workers: usize, admitted: bool, kind: &'static str, count: usize) -> (f64, u64) {
    let mut source = Memory::default();
    source.map(BASE, 2 * READ, Permissions::RW).unwrap();
    source
        .fill_with(BASE, 2 * READ as usize, |b| b.fill(42))
        .unwrap();
    source.protect(BASE, READ, Permissions::R).unwrap();
    let mut registry = Registry::default();
    let mut views: Vec<_> = (0..workers)
        .map(|_| source.parallel_view(&mut registry).unwrap())
        .collect();
    for (rank, view) in views.iter_mut().enumerate() {
        for at in (BASE..BASE + READ).step_by(4096) {
            black_box(view.read_u64(at).unwrap());
        }
        view.write_array(BASE + READ + rank as u64 * 4096, 42u64.to_le_bytes())
            .unwrap();
    }
    if admitted {
        // SAFETY: this is the complete View set for one immutable snapshot;
        // the source stays quiescent until all workers join. No host aliases.
        assert!(unsafe { View::try_private_epoch(&mut views.iter_mut().collect::<Vec<_>>()) });
        assert!(views.iter().all(View::readonly_private_enabled));
    }
    let gate = Arc::new(Barrier::new(workers + 1));
    let joins: Vec<_> = views
        .into_iter()
        .enumerate()
        .map(|(rank, mut view)| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                black_box(work(&mut view, rank, kind, count))
            })
        })
        .collect();
    let began = Instant::now();
    gate.wait();
    let checksum = joins
        .into_iter()
        .map(|j| j.join().unwrap())
        .fold(0u64, u64::wrapping_add);
    let seconds = began.elapsed().as_secs_f64();
    source.commit_parallel().unwrap();
    (seconds, checksum)
}
fn work(view: &mut View, rank: usize, kind: &str, count: usize) -> u64 {
    let mut sum = 0u64;
    for i in 0..count {
        match kind {
            "scalar-read" => {
                let at = BASE + ((i.wrapping_mul(17) & 2047) * 8) as u64;
                sum = sum.wrapping_add(view.read_u64(at).unwrap());
            }
            "native-pair64" => {
                let at = BASE + ((i & 31) * 64) as u64;
                let equal = view
                    .with_read_pair(at, at + 2048, 64, |a, b| black_box(a) == black_box(b))
                    .unwrap()
                    .0;
                sum += u64::from(equal);
            }
            "rw-control" => {
                let at = BASE + READ + rank as u64 * 4096 + ((i.wrapping_mul(17) & 511) * 8) as u64;
                let value = view.read_u64(at).unwrap().wrapping_add(1);
                view.write_array(at, value.to_le_bytes()).unwrap();
                sum = sum.wrapping_add(value);
            }
            _ => unreachable!(),
        }
    }
    sum
}
fn main() {
    let repeats: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "3".into())
        .parse()
        .unwrap();
    println!(
        "host={} page_bytes={} repeats={repeats} shared_vm=true",
        std::env::consts::ARCH,
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
    );
    for workers in [2, 4] {
        for (kind, count) in [
            ("scalar-read", 10_000_000),
            ("native-pair64", 5_000_000),
            ("rw-control", 5_000_000),
        ] {
            for repeat in 0..repeats {
                let mut checksum = None;
                for admitted in if repeat % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let (seconds, value) = sample(workers, admitted, kind, count);
                    assert!(checksum.replace(value).is_none_or(|old| old == value));
                    println!("workers={workers} kind={kind} mode={} repeat={repeat} iterations_per_worker={count} seconds={seconds:.9} checksum={value}", if admitted { "readonly" } else { "guarded" });
                }
            }
        }
    }
}
