// SPDX-License-Identifier: GPL-3.0-or-later
//! Static Bionic adapters, operating on the executing task's original memory.
use crate::native::{Error, Metrics, Return};
use trames_memory::NativeMemory;
pub const PROFILE: u64 = 0x0001_0009;
pub const FUNCTION_COUNT: u64 = 13;
fn done(value: u64) -> Result<Return, Error> {
    Ok(Return {
        value,
        fallback: false,
    })
}
fn fallback() -> Result<Return, Error> {
    Ok(Return {
        value: 0,
        fallback: true,
    })
}
fn u32_at(memory: &impl NativeMemory, at: u64) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(memory.native_read_array(at)?))
}
fn u64_at(memory: &impl NativeMemory, at: u64) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(memory.native_read_array(at)?))
}
fn jemalloc(memory: &mut impl NativeMemory, operation: u64, a: [u64; 3]) -> Result<Return, Error> {
    // The pinned guest block has already selected the nominal per-thread cache
    // and size class. Keep original guest TSD, bins, slots, ticker and stats;
    // the original miss/flush/arena/fork paths remain guest code.
    let tsd = a[0] & 0x00ff_ffff_ffff_ffff;
    let bin = if operation == 11 {
        tsd.wrapping_add(a[1].wrapping_mul(16)).wrapping_add(0x1d0)
    } else {
        a[1]
    } & 0x00ff_ffff_ffff_ffff;
    let count = u32_at(memory, bin + 4)? as i32;
    let ticker = u32_at(memory, tsd + 0x1c8)? as i32;
    if ticker <= 0 || count < 0 || (operation == 11 && count == 0) {
        return fallback();
    }
    let available = u64_at(memory, bin + 8)?;
    let (slot, value, low, allocated) = if operation == 11 {
        let slot = available.wrapping_sub((count as u64).wrapping_mul(8));
        let pointer = u64_at(memory, slot)?;
        if pointer == 0 {
            return fallback();
        }
        let low = u32_at(memory, bin)? as i32;
        let size = u64_at(memory, a[2].wrapping_add(a[1].wrapping_mul(8)))?;
        (
            slot,
            pointer,
            (count - 1 < low).then_some(count - 1),
            Some(u64_at(memory, tsd + 0x10)?.wrapping_add(size)),
        )
    } else {
        (
            available.wrapping_sub((count as u64 + 1).wrapping_mul(8)),
            a[2],
            None,
            None,
        )
    };
    // Admission uses the same memory model as CPU writes. No lock is added to
    // jemalloc's originally thread-owned fields, and there is no host heap alias.
    let outputs = [
        (bin + 4, 4),
        (tsd + 0x1c8, 4),
        (bin, if low.is_some() { 4 } else { 0 }),
        (tsd + 0x10, if operation == 11 { 8 } else { 0 }),
        (slot, if operation == 12 { 8 } else { 0 }),
    ];
    for (at, len) in outputs {
        if len != 0 && !memory.native_output_range(at, len)? {
            return fallback();
        }
    }
    if operation == 11 {
        memory.write_array(bin + 4, (count - 1).to_le_bytes())?;
        if let Some(low) = low {
            memory.write_array(bin, low.to_le_bytes())?;
        }
    } else {
        memory.write_array(bin + 4, count.wrapping_add(1).to_le_bytes())?;
        memory.write_array(slot, value.to_le_bytes())?;
    }
    memory.write_array(tsd + 0x1c8, (ticker - 1).to_le_bytes())?;
    if let Some(allocated) = allocated {
        memory.write_array(tsd + 0x10, allocated.to_le_bytes())?;
    }
    done(value)
}
#[inline(never)]
pub(crate) fn execute(
    memory: &mut impl NativeMemory,
    function: u64,
    a: [u64; 3],
    metrics: &mut Metrics,
) -> Result<Return, Error> {
    match function {
        1..=8 | 10 | 13 => crate::strings::search::execute(memory, function, a),
        9 => {
            if a[2] > 1 {
                return Err(Error::InvalidEntry);
            }
            let single = a[2] & 1 != 0;
            crate::numeric::parse_with_output::<24>(memory, a[0], a[1], metrics, false, |bytes| {
                // The bounded scanner determines whether a token reaches the
                // supplied fragment. Actual bits/errno use pinned Bionic gdtoa.
                let probe = trames_native::parse::floating(bytes, single);
                if probe.needs_more {
                    probe
                } else {
                    trames_native::parse::bionic_floating(bytes, single)
                }
            })
        }
        11 | 12 => jemalloc(memory, function, a),
        _ => fallback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn search_sets_and_case_comparison_stop_at_guard_page() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1ff5, b"AAAAxyzabc\0").unwrap();
        m.write(0x3000, b"xyZ\0").unwrap();
        assert_eq!(
            execute(
                &mut m,
                13,
                [0x1ff5, b'x' as u64, 0],
                &mut Metrics::default()
            )
            .unwrap()
            .value,
            0x1ff9
        );
        assert_eq!(
            execute(
                &mut m,
                13,
                [0x1ff5, b'q' as u64, 1],
                &mut Metrics::default()
            )
            .unwrap()
            .value,
            0x1fff
        );
        let mut metrics = Metrics::default();
        assert_eq!(
            execute(&mut m, 3, [0x1ff5, 0x3000, 3], &mut metrics)
                .unwrap()
                .value,
            0x1ff9
        );
        m.write(0x3000, b"xyz\0").unwrap();
        assert_eq!(
            execute(&mut m, 2, [0x1ff5, 0x3000, 3], &mut metrics)
                .unwrap()
                .value,
            0x1ff9
        );
        assert_eq!(
            execute(&mut m, 5, [0x1ff5, 0x3000, 0], &mut metrics)
                .unwrap()
                .value,
            4
        );
        assert_eq!(
            execute(&mut m, 6, [0x1ff5, 0x3000, 0], &mut metrics)
                .unwrap()
                .value,
            0x1ff9
        );
        m.write(0x3000, b"aAaAxYzAbC\0").unwrap();
        assert_eq!(
            execute(&mut m, 7, [0x1ff5, 0x3000, 0], &mut metrics)
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            execute(&mut m, 8, [0x4000, 0x5000, 0], &mut metrics)
                .unwrap()
                .value,
            0
        );
    }
    #[test]
    fn jemalloc_pop_push_preserve_original_bin_ticker_and_stats() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 8, Permissions::RW).unwrap();
        let tsd = 0x1000;
        let bin = tsd + 0x1e0;
        m.write_array(bin, 5i32.to_le_bytes()).unwrap();
        m.write_array(bin + 4, 3i32.to_le_bytes()).unwrap();
        m.write_array(bin + 8, 0x7000u64.to_le_bytes()).unwrap();
        m.write_array(0x7000 - 24, 0x8000u64.to_le_bytes()).unwrap();
        m.write_array(tsd + 0x1c8, 7i32.to_le_bytes()).unwrap();
        m.write_array(tsd + 0x10, 100u64.to_le_bytes()).unwrap();
        m.write_array(0x4008, 32u64.to_le_bytes()).unwrap();
        assert_eq!(
            jemalloc(&mut m, 11, [tsd, 1, 0x4000]).unwrap().value,
            0x8000
        );
        assert_eq!(u32_at(&m, bin).unwrap(), 2);
        assert_eq!(u32_at(&m, bin + 4).unwrap(), 2);
        assert_eq!(u32_at(&m, tsd + 0x1c8).unwrap(), 6);
        assert_eq!(u64_at(&m, tsd + 0x10).unwrap(), 132);
        jemalloc(&mut m, 12, [tsd, bin, 0x8100]).unwrap();
        assert_eq!(u32_at(&m, bin + 4).unwrap(), 3);
        assert_eq!(u32_at(&m, tsd + 0x1c8).unwrap(), 5);
        assert_eq!(u64_at(&m, 0x7000 - 24).unwrap(), 0x8100);
        m.write_array(tsd + 0x1c8, 0i32.to_le_bytes()).unwrap();
        let before = m.read_array::<16>(bin).unwrap();
        assert!(jemalloc(&mut m, 11, [tsd, 1, 0x4000]).unwrap().fallback);
        assert_eq!(before, m.read_array::<16>(bin).unwrap());
    }
}
