// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked, bounded string search/copy; original fallback before any writes.
use crate::native::{Error, Registry, Return, MAX_STRING_BYTES as MAX_BYTES};
#[cfg(test)]
use trames_memory::Memory;
use trames_memory::{NativeMemory, PAGE_SIZE};
pub(crate) fn execute(
    registry: &mut Registry,
    memory: &mut impl NativeMemory,
    function: u64,
    a: [u64; 3],
) -> Result<Return, Error> {
    if matches!(function, 18 | 19) {
        return concatenate(registry, memory, function == 19, a);
    }
    let [dst, src, length] = a;
    let fallback = || {
        Ok(Return {
            value: dst,
            fallback: true,
        })
    };
    let done = |value| {
        Ok(Return {
            value,
            fallback: false,
        })
    };
    let copy = function >= 14;
    let bounded = function >= 16;
    if bounded && length > MAX_BYTES as u64 {
        return fallback();
    }
    let limit = if bounded { length as usize } else { MAX_BYTES };
    let source = if copy { src } else { dst };
    let mut offset = 0;
    let mut last = None;
    let mut terminated = false;
    while offset < limit {
        let at = (source & 0x00ff_ffff_ffff_ffff) + offset as u64;
        let count = (limit - offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
        let ((nul, found), direct) = memory.with_read_chunk(at, count, |bytes| {
            let nul = trames_native::first_zero(bytes);
            let reached = &bytes[..nul.map_or(bytes.len(), |i| i + 1)];
            let found = if copy {
                None
            } else if function == 12 {
                trames_native::last_byte(reached, src as u8)
            } else {
                trames_native::first_byte(reached, src as u8)
            };
            (nul, found)
        })?;
        registry.record_read(count, direct);
        if let Some(index) = found {
            last = Some(offset + index);
            if function != 12 {
                return done(source.wrapping_add((offset + index) as u64));
            }
        }
        if let Some(index) = nul {
            offset += index;
            terminated = true;
            break;
        }
        offset += count;
    }
    if !terminated && !bounded {
        return fallback();
    }
    if !copy {
        return done(if function == 13 {
            source.wrapping_add(offset as u64)
        } else {
            last.map_or(0, |i| source.wrapping_add(i as u64))
        });
    }
    let total = if bounded { limit } else { offset + 1 };
    // All source reads and destination permissions are checked before effects.
    // Unknown I/O backings select original; resident shared/write-only output
    // is supported without granting the callback continuation this permission.
    match memory.native_output_range(dst, total) {
        Ok(true) => {}
        Ok(false) => return fallback(),
        Err(error) => return Err(error.into()),
    }
    let copied = if terminated { offset + 1 } else { offset };
    registry.record_transfer(memory.copy_with(dst, src, copied, trames_native::copy)?);
    if total > copied {
        registry.record_transfer(memory.fill_with(
            dst.wrapping_add(copied as u64),
            total - copied,
            |bytes| trames_native::fill(bytes, 0),
        )?);
    }
    done(if matches!(function, 15 | 17) {
        dst.wrapping_add(offset as u64)
    } else {
        dst
    })
}
/// Concatenation preflights both scans and the entire output before effects.
fn concatenate(
    registry: &mut Registry,
    memory: &mut impl NativeMemory,
    bounded: bool,
    [dst, src, length]: [u64; 3],
) -> Result<Return, Error> {
    let fallback = || {
        Ok(Return {
            value: dst,
            fallback: true,
        })
    };
    let mut scan = |address: u64, limit: usize| -> Result<(usize, bool), Error> {
        let mut offset = 0;
        while offset < limit {
            let at = (address & 0x00ff_ffff_ffff_ffff) + offset as u64;
            let count = (limit - offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            let (nul, direct) = memory.with_read_chunk(at, count, trames_native::first_zero)?;
            registry.record_read(count, direct);
            if let Some(index) = nul {
                return Ok((offset + index, true));
            }
            offset += count;
        }
        Ok((offset, false))
    };
    let (end, terminated) = scan(dst, MAX_BYTES)?;
    if !terminated {
        return fallback();
    }
    let (copied, terminated) = scan(
        src,
        if bounded {
            length.min(MAX_BYTES as u64) as usize
        } else {
            MAX_BYTES
        },
    )?;
    if !terminated && (!bounded || length > MAX_BYTES as u64) {
        return fallback();
    }
    let output = dst.wrapping_add(end as u64);
    match memory.native_output_range(output, copied + 1) {
        Ok(true) => {}
        Ok(false) => return fallback(),
        Err(error) => return Err(error.into()),
    }
    registry.record_transfer(memory.copy_with(output, src, copied, trames_native::copy)?);
    registry.record_transfer(
        memory.fill_with(output.wrapping_add(copied as u64), 1, |bytes| bytes.fill(0))?,
    );
    Ok(Return {
        value: dst,
        fallback: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{MemoryError, Permissions};
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
        m
    }
    #[test]
    fn concat_handles_page_splits_bounds_zero_guard_cow_and_no_partial_fallback() {
        let mut m = memory();
        let mut r = Registry::default();
        m.write(0x1ffe, b"ab\0").unwrap();
        m.write(0x3ffe, b"cde\0").unwrap();
        let parent = m.clone();
        let tagged = 0xab00_0000_0000_1ffe;
        assert_eq!(
            execute(&mut r, &mut m, 18, [tagged, 0x3ffe, 0])
                .unwrap()
                .value,
            tagged
        );
        assert_eq!(m.read_array::<6>(tagged).unwrap(), *b"abcde\0");
        assert_eq!(parent.read_array::<3>(tagged).unwrap(), *b"ab\0");
        assert!(
            !execute(&mut r, &mut m, 19, [tagged, 1, 0])
                .unwrap()
                .fallback
        );
        m.write(0x1ffe, b"ab\0").unwrap();
        assert!(
            !execute(&mut r, &mut m, 19, [tagged, 0x3ffe, 2])
                .unwrap()
                .fallback
        );
        assert_eq!(m.read_array::<5>(tagged).unwrap(), *b"abcd\0");
        m.write(0x1ffe, b"ab\0").unwrap();
        assert!(
            !execute(&mut r, &mut m, 19, [tagged, 0x3ffe, u64::MAX])
                .unwrap()
                .fallback
        );
        assert_eq!(m.read_array::<6>(tagged).unwrap(), *b"abcde\0");
        m.write(0x4ffd, b"ab\0").unwrap();
        assert!(execute(&mut r, &mut m, 18, [0x4ffd, 0x3ffe, 0]).is_err());
        assert_eq!(m.read_array::<3>(0x4ffd).unwrap(), *b"ab\0");
        assert!(
            execute(&mut r, &mut m, 16, [1, 1, MAX_BYTES as u64 + 1])
                .unwrap()
                .fallback
        );
    }

    #[test]
    fn searches_stop_at_nul_before_guard_and_preserve_unsigned_matches_and_tags() {
        let mut m = memory();
        let mut r = Registry::default();
        m.write(0x4ffc, &[255, b'x', 255, 0]).unwrap();
        let s = 0xab00_0000_0000_4ffc;
        for (function, c, expected) in [
            (11, 511, s),
            (12, 511, s + 2),
            (13, b'z' as u64, s + 3),
            (11, b'z' as u64, 0),
            (12, 0, s + 3),
        ] {
            assert_eq!(
                execute(&mut r, &mut m, function, [s, c, 0]).unwrap().value,
                expected
            );
        }
        m.write(0x4fff, &[1]).unwrap();
        assert!(matches!(
            execute(&mut r, &mut m, 12, [s, 511, 0]),
            Err(Error::Memory(MemoryError::Unmapped(0x5000)))
        ));
    }
    #[test]
    fn copies_preflight_whole_output_cow_padding_truncation_shared_and_writeonly() {
        let mut m = memory();
        let mut r = Registry::default();
        m.write(0x2ffe, b"abc\0").unwrap();
        m.write(0x4ffe, &[17; 2]).unwrap();
        assert!(execute(&mut r, &mut m, 14, [0x4ffe, 0x2ffe, 0]).is_err());
        assert_eq!(m.read_array::<2>(0x4ffe).unwrap(), [17; 2]);
        let parent = m.clone();
        let dst = 0xab00_0000_0000_1ffe;
        assert_eq!(
            execute(&mut r, &mut m, 15, [dst, 0x2ffe, 0]).unwrap().value,
            dst + 3
        );
        assert_eq!(m.read_array::<4>(dst).unwrap(), *b"abc\0");
        assert_eq!(parent.read_array::<4>(dst).unwrap(), [0; 4]);
        assert_eq!(
            execute(&mut r, &mut m, 17, [dst, 0x2ffe, 8]).unwrap().value,
            dst + 3
        );
        assert_eq!(m.read_array::<8>(dst).unwrap(), *b"abc\0\0\0\0\0");
        m.write(0x4ffe, b"xy").unwrap();
        assert_eq!(
            execute(&mut r, &mut m, 17, [dst, 0x4ffe, 2]).unwrap().value,
            dst + 2
        );
        assert_eq!(m.read_array::<3>(dst).unwrap(), *b"xyc");
        assert_eq!(execute(&mut r, &mut m, 17, [0, 0, 0]).unwrap().value, 0);
        m.map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, true)
            .unwrap();
        m.write(0x1000, &[17; 8]).unwrap();
        assert!(
            !execute(&mut r, &mut m, 16, [0x1000, 0x2ffe, 8])
                .unwrap()
                .fallback
        );
        assert_eq!(m.read_array::<8>(0x1000).unwrap(), *b"abc\0\0\0\0\0");
        m.protect(
            0x4000,
            PAGE_SIZE,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
        )
        .unwrap();
        assert!(
            !execute(&mut r, &mut m, 16, [0x4000, 0x2ffe, 8])
                .unwrap()
                .fallback
        );
        assert!(
            execute(&mut r, &mut m, 16, [0, 0, MAX_BYTES as u64 + 1])
                .unwrap()
                .fallback
        );
    }
}
