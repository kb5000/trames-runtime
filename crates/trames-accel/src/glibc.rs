// SPDX-License-Identifier: GPL-3.0-or-later
//! Paired Debian 13 conversion ABI; byte access is the common CPU transport.
use crate::native::{Error, Metrics, Return};
use trames_memory::NativeMemory;
pub const PROFILE: u64 = 0x0001_000a;
pub const FUNCTION_COUNT: u64 = 2;
pub(crate) fn execute(
    memory: &mut impl NativeMemory,
    function: u64,
    a: [u64; 3],
    metrics: &mut Metrics,
) -> Result<Return, Error> {
    match function {
        1 => {
            let base = a[2] as u32;
            if (base != 0 && !(2..=36).contains(&base)) || a[2] >> 34 != 0 {
                return Err(Error::InvalidEntry);
            }
            let result = crate::numeric::parse_with(memory, a[0], a[1], metrics, false, |bytes| {
                trames_native::glibc::integer(
                    bytes,
                    base,
                    a[2] & (1 << 32) != 0,
                    a[2] & (1 << 33) != 0,
                )
            })?;
            if !result.fallback {
                metrics.integer_conversions += 1;
            }
            Ok(result)
        }
        2 => {
            if a[2] > 1 {
                return Err(Error::InvalidEntry);
            }
            let single = a[2] != 0;
            let result = crate::numeric::parse_with_output::<24>(
                memory,
                a[0],
                a[1],
                metrics,
                false,
                |bytes| {
                    let probe = trames_native::parse::floating(bytes, single);
                    if probe.needs_more {
                        probe
                    } else {
                        trames_native::glibc::floating(bytes, single)
                    }
                },
            )?;
            if !result.fallback {
                metrics.numeric_conversions += 1;
            }
            Ok(result)
        }
        _ => Err(Error::InvalidEntry),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{Registry, INSTRUCTION};
    use trames_memory::{Memory, MemoryError, Permissions, PAGE_SIZE};
    fn memory(function: u64) -> Memory {
        let mut m = Memory::default();
        for at in [0x1000, 0x2000, 0x4000] {
            m.map(at, PAGE_SIZE, Permissions::RW).unwrap();
        }
        for (i, word) in [
            0xd2800150,
            0xf2a00030,
            0xd2800011 | ((function as u32) << 5),
            INSTRUCTION,
            0xd65f03c0,
        ]
        .into_iter()
        .enumerate()
        {
            m.write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m
    }
    #[test]
    fn glibc_entries_share_cpu_faults_and_retire_without_byte_limits() {
        let mut m = memory(1);
        m.write(0x4ffe, b"0b").unwrap();
        let mut r = Registry::default();
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 1, [0x4ffe, 0x2000, 0])
                .unwrap()
                .value,
            0
        );
        assert_eq!(m.read_u64(0x2000).unwrap(), 0x4fff);
        let before = m.read_array::<16>(0x2000).unwrap();
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 1, [0x4ffe, 0x2000, 1 << 33]),
            Err(Error::Memory(MemoryError::Unmapped(0x5000)))
        ));
        assert_eq!(m.read_array::<16>(0x2000).unwrap(), before);
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 1, [0x4000, 0x2000, 1]),
            Err(Error::InvalidEntry)
        ));
        let mut m = memory(2);
        m.write(0x4000, b"nan(123)!").unwrap();
        let mut r = Registry::default();
        assert_eq!(
            r.invoke(
                &mut m,
                0x100c,
                PROFILE,
                2,
                [0xab00_0000_0000_4000, 0x2000, 0]
            )
            .unwrap()
            .value,
            0x7ff8_0000_0000_007b
        );
        assert_eq!(m.read_u64(0x2000).unwrap(), 0xab00_0000_0000_4008);
        assert_eq!(r.metrics.glibc_operations, [0, 1]);
    }
}
