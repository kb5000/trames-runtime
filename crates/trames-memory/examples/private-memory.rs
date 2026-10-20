// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed-work A/B of the same CPU/native paths, excluding prepare/join costs.
//! Independent VMs: this does not measure shared-VM threads or whole-app speed.
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
const LENGTH: usize = 65536;

fn sample(workers: usize, exclusive: bool, kind: &str, count: usize) -> (f64, u64) {
    let mut sources: Vec<_> = (0..workers)
        .map(|_| {
            let mut memory = Memory::default();
            memory
                .map(BASE, 2 * LENGTH as u64, Permissions::RW)
                .unwrap();
            memory.fill_with(BASE, 2 * LENGTH, |b| b.fill(42)).unwrap();
            memory
        })
        .collect();
    let mut registry = Registry::default();
    let views: Vec<_> = sources
        .iter_mut()
        .map(|m| {
            let mut view = m.parallel_view(&mut registry).unwrap();
            if exclusive {
                // SAFETY: each worker owns a different VM's only View. Sources stay
                // idle until every worker joins; there are no shared/backed pages.
                assert!(unsafe { view.try_exclusive_private() });
            }
            // Populate local translations and residency before the timed work.
            for at in (BASE..BASE + 2 * LENGTH as u64).step_by(4096) {
                view.write_array(at, 42u64.to_le_bytes()).unwrap();
            }
            view
        })
        .collect();
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut joins = Vec::new();
    for mut view in views {
        let gate = barrier.clone();
        let kind = kind.to_owned();
        joins.push(std::thread::spawn(move || {
            gate.wait();
            let value = work(&mut view, &kind, count);
            black_box(value)
        }));
    }
    let began = Instant::now();
    barrier.wait();
    let checksum = joins
        .into_iter()
        .map(|j| j.join().unwrap())
        .fold(0u64, u64::wrapping_add);
    let seconds = began.elapsed().as_secs_f64();
    for source in &mut sources {
        source.commit_parallel().unwrap();
    }
    (seconds, checksum)
}
fn work(view: &mut View, kind: &str, count: usize) -> u64 {
    match kind {
        "scalar" => {
            let mut sum = 0u64;
            for i in 0..count {
                let at = BASE + ((i.wrapping_mul(17) & 2047) * 8) as u64;
                let n = view.read_u64(at).unwrap().wrapping_add(1);
                view.write_array(at, n.to_le_bytes()).unwrap();
                sum = sum.wrapping_add(n);
            }
            sum
        }
        "native64" | "native64k" => {
            let len = if kind == "native64" { 64 } else { LENGTH };
            for i in 0..count {
                view.fill_with(BASE, len, |b| b.fill(i as u8)).unwrap();
                view.copy_with(BASE + LENGTH as u64, BASE, len, |d, s| d.copy_from_slice(s))
                    .unwrap();
            }
            view.with_read_chunk(BASE + LENGTH as u64, 64, |b| {
                b.iter().map(|&v| v as u64).sum()
            })
            .unwrap()
            .0
        }
        _ => unreachable!(),
    }
}
fn main() {
    let repeats: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "3".into())
        .parse()
        .unwrap();
    println!(
        "host={} page_bytes={} repeats={repeats}",
        std::env::consts::ARCH,
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
    );
    for workers in [1, 4] {
        for (kind, count) in [
            ("scalar", 10_000_000),
            ("native64", 2_000_000),
            ("native64k", 10_000),
        ] {
            for repeat in 0..repeats {
                for exclusive in if repeat % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let (seconds, checksum) = sample(workers, exclusive, kind, count);
                    println!("workers={workers} kind={kind} mode={} repeat={repeat} iterations_per_worker={count} seconds={seconds:.9} checksum={checksum}", if exclusive { "private" } else { "guarded" });
                }
            }
        }
    }
}
