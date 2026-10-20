// SPDX-License-Identifier: GPL-3.0-or-later
//! Compare physical storage, not RSS summed across aliases of the same pages.
use std::time::Instant;
use trames_memory::{parallel::Registry, CpuMemory, Memory, Permissions, PAGE_SIZE};
fn footprint() -> String {
    std::fs::read_to_string("/proc/self/smaps_rollup")
        .map(|text| {
            text.lines()
                .filter(|line| {
                    line.starts_with("Rss:")
                        || line.starts_with("Pss:")
                        || line.starts_with("Private_Dirty:")
                        || line.starts_with("Shared_Dirty:")
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_else(|_| "smaps_rollup unavailable on this host".into())
}
fn main() {
    let mib: u64 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "128".into())
        .parse()
        .unwrap();
    let length = mib * 1024 * 1024;
    let base = 0x10000000;
    let mut memory = Memory::new(length as usize + 1024 * 1024);
    memory.map(base, length, Permissions::RW).unwrap();
    for address in (base..base + length).step_by(PAGE_SIZE as usize) {
        memory.write_array(address, 42u64.to_le_bytes()).unwrap();
    }
    println!("source_mib={mib} before: {}", footprint());
    let mut registry = Registry::default();
    let started = Instant::now();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    let views: Vec<_> = (0..4).map(|_| view.clone()).collect();
    let publish = started.elapsed();
    for reader in &views {
        for address in (base..base + length).step_by(PAGE_SIZE as usize) {
            assert_eq!(reader.read_u64(address).unwrap(), 42);
        }
    }
    println!(
        "four_views publish_ms={:.3} after: {}",
        publish.as_secs_f64() * 1000.,
        footprint()
    );
    let started = Instant::now();
    for address in (base..base + length).step_by(PAGE_SIZE as usize) {
        view.write_array(address, 43u64.to_le_bytes()).unwrap();
    }
    drop((view, views));
    let stores = started.elapsed();
    let started = Instant::now();
    memory.commit_parallel().unwrap();
    let commit = started.elapsed();
    for address in (base..base + length).step_by(PAGE_SIZE as usize) {
        assert_eq!(memory.read_u64(address).unwrap(), 43);
    }
    println!(
        "store_ms={:.3} commit_ms={:.3} final: {}",
        stores.as_secs_f64() * 1000.,
        commit.as_secs_f64() * 1000.,
        footprint()
    );
    println!("{:?}", registry.metrics);
}
