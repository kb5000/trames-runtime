// SPDX-License-Identifier: GPL-3.0-or-later
//! Original musl intscan, using the numeric module's checked page transport.
use crate::native::{Error, Metrics, Return};
#[cfg(test)]
use trames_memory::Memory;
use trames_memory::NativeMemory;
pub const AUXV_KEY: u64 = 0x5452_0006;
pub const PROFILE: u64 = 0x0001_0004;
pub(crate) fn parse(
    memory: &mut impl NativeMemory,
    a: [u64; 3],
    metrics: &mut Metrics,
) -> Result<Return, Error> {
    let [source, output, mode] = a;
    if mode >> 33 != 0 {
        return Err(Error::InvalidEntry);
    }
    let base = mode as u32;
    let signed = mode & (1 << 32) != 0;
    let result = crate::numeric::parse_with(
        memory,
        source,
        output,
        metrics,
        base == 1 || base > 36,
        |bytes| trames_native::parse::integer(bytes, base, signed),
    )?;
    if !result.fallback {
        metrics.integer_conversions = metrics.integer_conversions.saturating_add(1);
    }
    Ok(result)
}
/// musl atoi/atol/atoll accumulate negatively with width wrapping and leave
/// errno unchanged. Their overflow behavior differs from saturating strtoll.
pub(crate) fn plain(
    memory: &impl NativeMemory,
    [source, bits, _]: [u64; 3],
) -> Result<Return, Error> {
    if !matches!(bits, 32 | 64) {
        return Err(Error::InvalidEntry);
    }
    let (mut state, mut negative, mut value, mut offset) = (0u8, false, 0u64, 0u64);
    loop {
        let at = source.wrapping_add(offset);
        let count = (trames_memory::PAGE_SIZE
            - (at & 0x00ff_ffff_ffff_ffff) % trames_memory::PAGE_SIZE) as usize;
        let (done, _) = memory.with_read_chunk(at, count, |bytes| {
            for &c in bytes {
                if state == 0 {
                    if c == b' ' || (b'\t'..=b'\r').contains(&c) {
                        continue;
                    }
                    state = 1;
                    if matches!(c, b'+' | b'-') {
                        negative = c == b'-';
                        continue;
                    }
                }
                if !c.is_ascii_digit() {
                    return true;
                }
                value = value.wrapping_mul(10).wrapping_sub((c - b'0') as u64);
            }
            false
        })?;
        if done {
            if !negative {
                value = 0u64.wrapping_sub(value);
            }
            return Ok(Return {
                value: if bits == 32 {
                    value as u32 as u64
                } else {
                    value
                },
                fallback: false,
            });
        }
        offset += count as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn invalid_bases_do_not_read_input_and_boundary_end_keeps_tags() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let mut metrics = Metrics::default();
        let result = parse(&mut memory, [0, 0x1000, 1], &mut metrics).unwrap();
        assert_eq!(
            result,
            Return {
                value: 0,
                fallback: false
            }
        );
        assert_eq!(
            memory.read_array::<16>(0x1000).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0]
        );
        memory.write(0x2ffd, b"7f!").unwrap();
        let tag = 0xab00_0000_0000_2ffd;
        assert_eq!(
            parse(&mut memory, [tag, 0x1000, 16 | (1 << 32)], &mut metrics)
                .unwrap()
                .value,
            127
        );
        assert_eq!(
            u64::from_le_bytes(memory.read_array(0x1000).unwrap()),
            tag + 2
        );
        assert_eq!(metrics.integer_conversions, 2);
        assert_eq!(metrics.numeric_conversions, 0);
    }
}
