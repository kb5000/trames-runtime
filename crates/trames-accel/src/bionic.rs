// SPDX-License-Identifier: GPL-3.0-or-later
//! Static Bionic adapters, operating on the executing task's original memory.
use crate::native::{Error, Metrics, Return, MAX_BULK_BYTES, MAX_BYTES};
use trames_memory::{NativeMemory, PAGE_SIZE};
pub const PROFILE: u64 = 0x0001_0009;
pub const FUNCTION_COUNT: u64 = 13;
const MORE: u64 = u64::MAX;
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
fn fold(c: u8) -> u8 {
    if c.is_ascii_uppercase() {
        c + 32
    } else {
        c
    }
}
fn chunk(at: u64, left: usize) -> usize {
    left.min((PAGE_SIZE - (at & 0x00ff_ffff_ffff_ffff) % PAGE_SIZE) as usize)
}
fn string(memory: &impl NativeMemory, at: u64) -> Result<Option<Vec<u8>>, Error> {
    let mut out = Vec::new();
    while out.len() < MAX_BYTES {
        let pos = at.wrapping_add(out.len() as u64);
        let count = chunk(pos, MAX_BYTES - out.len());
        let (end, _) = memory.with_read_chunk(pos, count, |bytes| {
            let end = bytes.iter().position(|&x| x == 0);
            out.extend_from_slice(&bytes[..end.unwrap_or(bytes.len())]);
            end.is_some()
        })?;
        if end {
            return Ok(Some(out));
        }
    }
    Ok(None)
}
fn search(memory: &impl NativeMemory, function: u64, a: [u64; 3]) -> Result<Return, Error> {
    let (hay, needle, length, needle_len) = if function == 1 {
        let request = memory.native_read_array::<32>(a[0])?;
        let words: [u64; 4] = std::array::from_fn(|i| {
            u64::from_le_bytes(request[i * 8..i * 8 + 8].try_into().unwrap())
        });
        (words[0], words[2], words[1], words[3])
    } else {
        (a[0], a[1], u64::MAX, a[2])
    };
    if needle_len == 0 {
        return done(hay);
    }
    if function == 1 && needle_len > length {
        return done(0);
    }
    if needle_len > MAX_BYTES as u64 {
        return fallback();
    }
    // Common short patterns keep both scratch arrays on this call's stack.
    let mut small_pattern = [0u8; 32];
    let mut large_pattern;
    let pattern = if needle_len <= 32 {
        &mut small_pattern[..needle_len as usize]
    } else {
        large_pattern = vec![0; needle_len as usize];
        &mut large_pattern[..]
    };
    memory.native_read(needle, pattern)?;
    if function == 3 {
        pattern.iter_mut().for_each(|c| *c = fold(*c));
    }
    // KMP keeps repeated-prefix inputs linear. Scratch belongs only to this
    // call; no guest pointers, locks or continuation survive the native entry.
    let mut small_prefix = [0usize; 32];
    let mut large_prefix;
    let prefix = if pattern.len() <= 32 {
        &mut small_prefix[..pattern.len()]
    } else {
        large_prefix = vec![0usize; pattern.len()];
        &mut large_prefix[..]
    };
    for i in 1..pattern.len() {
        let mut j = prefix[i - 1];
        while j != 0 && pattern[i] != pattern[j] {
            j = prefix[j - 1];
        }
        if pattern[i] == pattern[j] {
            j += 1;
        }
        prefix[i] = j;
    }
    let budget = length.min(MAX_BULK_BYTES as u64) as usize;
    let (mut offset, mut matched) = (0usize, 0usize);
    while offset < budget {
        let at = hay.wrapping_add(offset as u64);
        let count = chunk(at, budget - offset);
        let (answer, _) = memory.with_read_chunk(at, count, |bytes| {
            let mut i = 0;
            while i < bytes.len() {
                if matched == 0 {
                    // Keep the existing vector scan for unmatched prefixes;
                    // the failure table handles repeated candidates linearly.
                    let rest = &bytes[i..];
                    let mut candidate = trames_native::first_byte(rest, pattern[0]);
                    if function == 3 && pattern[0].is_ascii_lowercase() {
                        if let Some(upper) = trames_native::first_byte(rest, pattern[0] - 32) {
                            candidate = Some(candidate.map_or(upper, |lower| lower.min(upper)));
                        }
                    }
                    let skip = candidate.unwrap_or(rest.len());
                    if function != 1 && trames_native::first_zero(&rest[..skip]).is_some() {
                        return Some(0);
                    }
                    i += skip;
                    if i == bytes.len() {
                        break;
                    }
                }
                let byte = bytes[i];
                if function != 1 && byte == 0 {
                    return Some(0);
                }
                let byte = if function == 3 { fold(byte) } else { byte };
                while matched != 0 && byte != pattern[matched] {
                    matched = prefix[matched - 1];
                }
                if byte == pattern[matched] {
                    matched += 1;
                }
                if matched == pattern.len() {
                    return Some(hay.wrapping_add((offset + i + 1 - pattern.len()) as u64));
                }
                i += 1;
            }
            None
        })?;
        if let Some(answer) = answer {
            return done(answer);
        }
        offset += count;
    }
    done(if length > budget as u64 { MORE } else { 0 })
}
fn span(memory: &impl NativeMemory, function: u64, a: [u64; 3]) -> Result<Return, Error> {
    let Some(set) = string(memory, a[1])? else {
        return fallback();
    };
    let mut table = [false; 256];
    for c in set {
        table[c as usize] = true;
    }
    let mut offset = 0;
    while offset < MAX_BULK_BYTES {
        let count = chunk(a[0].wrapping_add(offset as u64), MAX_BULK_BYTES - offset);
        let (answer, _) =
            memory.with_read_chunk(a[0].wrapping_add(offset as u64), count, |bytes| {
                for (i, &c) in bytes.iter().enumerate() {
                    let stop = c == 0
                        || if function == 4 {
                            !table[c as usize]
                        } else {
                            table[c as usize]
                        };
                    if stop {
                        return Some(if function == 6 {
                            if c == 0 {
                                0
                            } else {
                                a[0].wrapping_add((offset + i) as u64)
                            }
                        } else {
                            (offset + i) as u64
                        });
                    }
                }
                None
            })?;
        if let Some(answer) = answer {
            return done(answer);
        }
        offset += count;
    }
    done(MORE)
}
fn compare(memory: &impl NativeMemory, function: u64, a: [u64; 3]) -> Result<Return, Error> {
    let bound = if function == 7 { u64::MAX } else { a[2] };
    let limit = bound.min(MAX_BULK_BYTES as u64) as usize;
    let mut offset = 0;
    while offset < limit {
        let left = a[0].wrapping_add(offset as u64);
        let right = a[1].wrapping_add(offset as u64);
        let count = chunk(left, chunk(right, limit - offset));
        let (answer, _, _) = memory.with_read_pair(left, right, count, |l, r| {
            for (&x, &y) in l.iter().zip(r) {
                let x = if function == 10 { x } else { fold(x) };
                let y = if function == 10 { y } else { fold(y) };
                if x != y || x == 0 {
                    return Some((x as i32 - y as i32) as u32 as u64);
                }
            }
            None
        })?;
        if let Some(answer) = answer {
            return done(answer);
        }
        offset += count;
    }
    done(if bound > limit as u64 { MORE } else { 0 })
}
fn find_character(memory: &impl NativeMemory, a: [u64; 3]) -> Result<Return, Error> {
    let mut offset = 0;
    while offset < MAX_BULK_BYTES {
        let at = a[0].wrapping_add(offset as u64);
        let count = chunk(at, MAX_BULK_BYTES - offset);
        let (answer, _) = memory.with_read_chunk(at, count, |bytes| {
            for (i, &c) in bytes.iter().enumerate() {
                if c == a[1] as u8 {
                    return Some(at.wrapping_add(i as u64));
                }
                if c == 0 {
                    return Some(if a[2] != 0 {
                        at.wrapping_add(i as u64)
                    } else {
                        0
                    });
                }
            }
            None
        })?;
        if let Some(answer) = answer {
            return done(answer);
        }
        offset += count;
    }
    done(MORE)
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
        1..=3 => search(memory, function, a),
        4..=6 => span(memory, function, a),
        7 | 8 | 10 => compare(memory, function, a),
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
        13 => find_character(memory, a),
        _ => fallback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
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
