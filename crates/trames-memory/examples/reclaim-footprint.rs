// SPDX-License-Identifier: GPL-3.0-or-later
//! Real guest Memory, retained partial arenas, repeated release and data reuse.
use trames_memory::{Memory, Permissions, PAGE_SIZE};

#[cfg(target_vendor = "apple")]
fn footprint() -> u64 {
    // SAFETY: the SDK's exact rusage_info_v2 layout and a writable complete
    // output buffer; proc_pid_rusage reads only this process's accounting.
    unsafe {
        let mut usage: libc::rusage_info_v2 = std::mem::zeroed();
        assert_eq!(
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V2,
                (&mut usage as *mut libc::rusage_info_v2).cast()
            ),
            0
        );
        usage.ri_phys_footprint
    }
}
#[cfg(not(target_vendor = "apple"))]
fn footprint() -> u64 {
    let data = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: u64 = data.split_whitespace().nth(1).unwrap().parse().unwrap();
    // SAFETY: sysconf has no pointer arguments.
    pages * unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}
fn report(phase: &str, cycle: usize, memory: &Memory) -> u64 {
    let bytes = footprint();
    println!(
        "{{\"phase\":\"{phase}\",\"cycle\":{cycle},\"guest_resident\":{},\"host_bytes\":{bytes}}}",
        memory.resident_bytes()
    );
    bytes
}
fn main() {
    const WINDOW: u64 = 1 << 20;
    const LENGTH: u64 = 64 * WINDOW;
    const BASE: u64 = 0x100000;
    // SAFETY: sysconf has no pointer arguments.
    let granule = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let mut memory = Memory::default();
    report("baseline", 0, &memory);
    for cycle in 1..=3 {
        for window in 0..64 {
            let at = BASE + window * WINDOW;
            if cycle == 1 {
                memory.map(at, WINDOW, Permissions::RW).unwrap();
            } else {
                memory
                    .map(at + granule, WINDOW - granule, Permissions::RW)
                    .unwrap();
            }
        }
        for offset in (0..LENGTH).step_by(PAGE_SIZE as usize) {
            memory
                .write_array(BASE + offset, (offset + cycle as u64).to_le_bytes())
                .unwrap();
        }
        let high = report("populated_64m", cycle, &memory);
        for window in 0..64 {
            // Leave one host granule in EVERY arena: whole-window release is
            // insufficient to pass this test of real partial-arena reclamation.
            let at = BASE + window * WINDOW;
            memory.unmap(at + granule, WINDOW - granule).unwrap();
            assert_eq!(
                memory.read_array::<8>(at).unwrap(),
                (window * WINDOW + cycle as u64).to_le_bytes()
            );
        }
        let low = report("released_all_but_64_granules", cycle, &memory);
        assert!(high >= low + 48 * WINDOW, "actual host charge did not fall");
        assert_eq!(memory.resident_bytes() as u64, 64 * granule);
    }
    memory.unmap(BASE, LENGTH).unwrap();
    report("released_all", 0, &memory);
}
