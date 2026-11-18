// SPDX-License-Identifier: GPL-3.0-or-later
//! Complete pure string algorithms shared by musl and Bionic adapters.
use crate::native::{Error, Return};
use trames_memory::{NativeMemory, PAGE_SIZE};
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
    loop {
        let pos = at.wrapping_add(out.len() as u64);
        let count = chunk(pos, PAGE_SIZE as usize);
        let (end, _) = memory.with_read_chunk(pos, count, |bytes| {
            let end = bytes.iter().position(|&x| x == 0);
            let bytes = &bytes[..end.unwrap_or(bytes.len())];
            if out.try_reserve(bytes.len()).is_err() {
                return None;
            }
            out.extend_from_slice(bytes);
            Some(end.is_some())
        })?;
        match end {
            Some(true) => return Ok(Some(out)),
            Some(false) => {}
            None => return Ok(None),
        }
    }
}
fn search(memory: &impl NativeMemory, function: u64, a: [u64; 3]) -> Result<Return, Error> {
    let (hay, needle, length, mut needle_len) = if function == 1 {
        let request = memory.native_read_array::<32>(a[0])?;
        let words: [u64; 4] = std::array::from_fn(|i| {
            u64::from_le_bytes(request[i * 8..i * 8 + 8].try_into().unwrap())
        });
        (words[0], words[2], words[1], words[3])
    } else {
        (a[0], a[1], u64::MAX, a[2])
    };
    let discovered = if function != 1 && needle_len == 0 {
        let Some(pattern) = string(memory, needle)? else {
            return fallback();
        };
        needle_len = pattern.len() as u64;
        Some(pattern)
    } else {
        None
    };
    if needle_len == 0 {
        return done(hay);
    }
    if function == 1 && needle_len > length {
        return done(0);
    }
    // Common short patterns keep both scratch arrays on this call's stack.
    let mut small_pattern = [0u8; 32];
    let mut large_pattern;
    let pattern = if needle_len <= 32 {
        &mut small_pattern[..needle_len as usize]
    } else {
        large_pattern = discovered.unwrap_or_default();
        while large_pattern.len() < needle_len as usize {
            let at = needle.wrapping_add(large_pattern.len() as u64);
            let count = chunk(at, needle_len as usize - large_pattern.len());
            let (copied, _) = memory.with_read_chunk(at, count, |bytes| {
                if large_pattern.try_reserve(bytes.len()).is_err() {
                    return false;
                }
                large_pattern.extend_from_slice(bytes);
                true
            })?;
            if !copied {
                return fallback();
            }
        }
        &mut large_pattern[..]
    };
    if needle_len <= 32 {
        memory.native_read(needle, pattern)?;
    }
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
        large_prefix = Vec::new();
        if large_prefix.try_reserve_exact(pattern.len()).is_err() {
            return fallback();
        }
        large_prefix.resize(pattern.len(), 0usize);
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
    let budget = length as usize;
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
    done(0)
}
fn span(memory: &impl NativeMemory, function: u64, a: [u64; 3]) -> Result<Return, Error> {
    let mut table = [false; 256];
    let (mut members, mut single) = (0usize, 0u8);
    let mut set_at = a[1];
    loop {
        let count = chunk(set_at, PAGE_SIZE as usize);
        let (end, _) = memory.with_read_chunk(set_at, count, |bytes| {
            for &c in bytes {
                if c == 0 {
                    return true;
                }
                if !table[c as usize] {
                    members += 1;
                    single = c;
                }
                table[c as usize] = true;
            }
            false
        })?;
        if end {
            break;
        }
        set_at = set_at.wrapping_add(count as u64);
    }
    if members == 0 && matches!(function, 4 | 6) {
        return done(0);
    }
    // Encode NUL in the table and choose the stop value once, rather than
    // testing the operation kind and NUL separately for every input byte.
    let stop = function != 4;
    table[0] = stop;
    let mut offset = 0;
    while offset < usize::MAX {
        let at = a[0].wrapping_add(offset as u64);
        let count = chunk(at, usize::MAX - offset);
        let (answer, _) = memory.with_read_chunk(at, count, |bytes| {
            let found = if members == 0 {
                trames_native::first_zero(bytes)
            } else if members == 1 {
                if function == 4 {
                    trames_native::first_not_byte(bytes, single)
                } else {
                    match (
                        trames_native::first_byte(bytes, single),
                        trames_native::first_zero(bytes),
                    ) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    }
                }
            } else {
                bytes.iter().position(|&c| table[c as usize] == stop)
            };
            found.map(|i| {
                if function == 6 {
                    if bytes[i] == 0 {
                        0
                    } else {
                        at.wrapping_add(i as u64)
                    }
                } else {
                    (offset + i) as u64
                }
            })
        })?;
        if let Some(answer) = answer {
            return done(answer);
        }
        offset += count;
    }
    done(0)
}
fn compare(memory: &impl NativeMemory, function: u64, a: [u64; 3]) -> Result<Return, Error> {
    let bound = if function == 7 { u64::MAX } else { a[2] };
    let limit = bound as usize;
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
    done(0)
}
fn find_character(memory: &impl NativeMemory, a: [u64; 3]) -> Result<Return, Error> {
    let mut offset = 0;
    while offset < usize::MAX {
        let at = a[0].wrapping_add(offset as u64);
        let count = chunk(at, usize::MAX - offset);
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
    done(0)
}

#[inline(never)]
pub(crate) fn execute(
    memory: &impl NativeMemory,
    function: u64,
    a: [u64; 3],
) -> Result<Return, Error> {
    match function {
        1..=3 => search(memory, function, a),
        4..=6 => span(memory, function, a),
        7 | 8 | 10 => compare(memory, function, a),
        13 => find_character(memory, a),
        _ => Err(Error::InvalidEntry),
    }
}
