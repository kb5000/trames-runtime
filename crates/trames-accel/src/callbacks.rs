// SPDX-License-Identifier: GPL-3.0-or-later
//! Smoothsort algorithm copyright (C) 2011 Valentin Ochs, MIT; complete original
//! notice: trames-native/upstream/musl-1.2.5/stdlib/qsort.c and bundled musl notice.
//! Guest-owned resumable Smoothsort/bsearch. See pinned musl sources and notices.
//! The callback is executed by ordinary guest code; no host frame or borrow survives.
use crate::native::{Error, Metrics, Return, MAX_BYTES};
#[cfg(test)]
use trames_memory::Memory;
use trames_memory::{Access, NativeMemory};
pub const AUXV_KEY: u64 = 0x5452_0003;
/// Public bsearch routing is experimental: generic callback entry costs more
/// than its short interpreted loop. The backend remains available for testing.
pub const SEARCH_AUXV_KEY: u64 = 0x5452_0004;
pub const PROFILE: u64 = 0x0001_0002;
pub const VERSION: u64 = 0x5452_5301;
pub const WORDS: usize = 240;
pub const FRAME_BYTES: usize = WORDS * 8;
pub const DONE: u64 = 0;
pub const COMPARE: u64 = 1;
pub const YIELD: u64 = 2;
// Shared with accelerator/musl/callbacks.h. Values are serialized LP64 words.
const KIND: usize = 1;
const PC: usize = 2;
const BASE: usize = 3;
const NEL: usize = 4;
const WIDTH: usize = 5;
const KEY: usize = 6;
const LEFT: usize = 7;
const RIGHT: usize = 8;
const RESULT: usize = 9;
const HEAD: usize = 10;
const HIGH: usize = 11;
const P: usize = 12;
const SHIFT: usize = 14;
const RETURN: usize = 15;
const SUBHEAD: usize = 16;
const SUBP: usize = 17;
const SUBSHIFT: usize = 19;
const TRUSTY: usize = 20;
const COUNT: usize = 21;
const OFFSET: usize = 22;
const CYCLE_RETURN: usize = 23;
const LP: usize = 24;
const AR: usize = 120;
const PATH: usize = 113;
const FINISHED: u64 = 255;

struct Frame([u64; WORDS]);
impl Frame {
    fn invalid<T>() -> Result<T, Error> {
        Err(Error::InvalidEntry)
    }
    fn address(&self, offset: u64) -> Result<u64, Error> {
        if self.0[WIDTH] == 0 || offset > self.0[HIGH] || !offset.is_multiple_of(self.0[WIDTH]) {
            return Self::invalid();
        }
        self.0[BASE].checked_add(offset).ok_or(Error::InvalidEntry)
    }
    fn lp(&self, shift: u64) -> Result<u64, Error> {
        if shift >= 96 {
            return Self::invalid();
        }
        Ok(self.0[LP + shift as usize])
    }
    fn subtract(head: u64, amount: u64) -> Result<u64, Error> {
        head.checked_sub(amount).ok_or(Error::InvalidEntry)
    }
    fn pair_shift(&mut self, index: usize, count: u64, left: bool) -> Result<(), Error> {
        if count >= 128 {
            return Self::invalid();
        }
        let mut p = u128::from(self.0[index]) | (u128::from(self.0[index + 1]) << 64);
        if left {
            p <<= count;
        } else {
            p >>= count;
        }
        self.0[index] = p as u64;
        self.0[index + 1] = (p >> 64) as u64;
        Ok(())
    }
    fn trail(&self, index: usize) -> u64 {
        // musl's generic de Bruijn a_ctz_l returns zero for zero input.
        let zeroes = |x: u64| {
            if x == 0 {
                0
            } else {
                u64::from(x.trailing_zeros())
            }
        };
        let r = zeroes(self.0[index].wrapping_sub(1));
        if r != 0 {
            return r;
        }
        let r = 64 + zeroes(self.0[index + 1]);
        if r == 64 {
            0
        } else {
            r
        }
    }
    fn append(&mut self, offset: u64) -> Result<(), Error> {
        self.address(offset)?;
        let count = self.0[COUNT];
        if count >= PATH as u64 {
            return Self::invalid();
        }
        self.0[AR + count as usize] = offset;
        self.0[COUNT] += 1;
        Ok(())
    }
    fn subroutine(&mut self, phase: u64, head: u64, shift: u64, trusty: u64, resume: u64) {
        self.0[SUBHEAD] = head;
        self.0[SUBSHIFT] = shift;
        self.0[TRUSTY] = trusty;
        self.0[SUBP] = self.0[P];
        self.0[SUBP + 1] = self.0[P + 1];
        self.0[RETURN] = resume;
        self.0[PC] = phase;
    }
    fn compare(&mut self, left: u64, right: u64, next: u64) -> Result<u64, Error> {
        self.0[LEFT] = self.address(left)?;
        self.0[RIGHT] = self.address(right)?;
        self.0[PC] = next;
        Ok(COMPARE)
    }
    fn cycle(&mut self, next: u64) {
        self.0[OFFSET] = 0;
        self.0[CYCLE_RETURN] = next;
        self.0[PC] = 48;
    }
    fn children(&self) -> Result<(u64, u64), Error> {
        let right = Self::subtract(self.0[SUBHEAD], self.0[WIDTH])?;
        let left = Self::subtract(right, self.lp(Self::subtract(self.0[SUBSHIFT], 2)?)?)?;
        Ok((left, right))
    }
    fn run_sort(
        &mut self,
        memory: &mut impl NativeMemory,
        cmp: i32,
        metrics: &mut Metrics,
    ) -> Result<u64, Error> {
        let width = self.0[WIDTH];
        let size = width.checked_mul(self.0[NEL]).ok_or(Error::InvalidEntry)?;
        if width == 0
            || self.0[NEL] < 2
            || size > MAX_BYTES as u64
            || self.0[HIGH] != size - width
            || self.0[SHIFT] >= 96
            || self.0[SUBSHIFT] >= 96
        {
            return Self::invalid();
        }
        // A guest comparator can issue a mapping syscall between steps. Gate
        // the complete array again before any cycle writes, so a worker defer
        // cannot occur after partially moving another resident fragment.
        if !memory.native_writable_range(self.0[BASE], size as usize)? {
            return Self::invalid();
        }
        // Limit native control-flow and copied bytes independently of comparisons.
        let mut moved = 0;
        for _ in 0..256 {
            match self.0[PC] {
                1 => {
                    if self.0[HEAD] == self.0[HIGH] {
                        self.subroutine(32, self.0[HEAD], self.0[SHIFT], 0, 4);
                    } else if self.0[HEAD] < self.0[HIGH] {
                        if self.0[P] & 3 == 3 {
                            self.subroutine(16, self.0[HEAD], self.0[SHIFT], 0, 2);
                        } else {
                            let shift = Self::subtract(self.0[SHIFT], 1)?;
                            let near_end = self.lp(shift)? >= self.0[HIGH] - self.0[HEAD];
                            self.subroutine(
                                if near_end { 32 } else { 16 },
                                self.0[HEAD],
                                self.0[SHIFT],
                                0,
                                3,
                            );
                        }
                    } else {
                        return Self::invalid();
                    }
                }
                2 => {
                    self.pair_shift(P, 2, false)?;
                    self.0[SHIFT] += 2;
                    self.0[PC] = 8;
                }
                3 => {
                    if self.0[SHIFT] == 1 {
                        self.pair_shift(P, 1, true)?;
                        self.0[SHIFT] = 0;
                    } else {
                        self.pair_shift(P, Self::subtract(self.0[SHIFT], 1)?, true)?;
                        self.0[SHIFT] = 1;
                    }
                    self.0[PC] = 8;
                }
                8 => {
                    self.0[P] |= 1;
                    self.0[HEAD] = self.0[HEAD].checked_add(width).ok_or(Error::InvalidEntry)?;
                    self.0[PC] = 1;
                }
                4 => {
                    self.0[PC] = 5;
                }
                5 => {
                    if self.0[SHIFT] == 1 && self.0[P] == 1 && self.0[P + 1] == 0 {
                        self.0[PC] = FINISHED;
                        return Ok(DONE);
                    }
                    if self.0[SHIFT] <= 1 {
                        let trail = self.trail(P);
                        self.pair_shift(P, trail, false)?;
                        self.0[SHIFT] += trail;
                        self.0[HEAD] = Self::subtract(self.0[HEAD], width)?;
                    } else {
                        self.pair_shift(P, 2, true)?;
                        self.0[SHIFT] -= 2;
                        self.0[P] ^= 7;
                        self.pair_shift(P, 1, false)?;
                        let head = Self::subtract(
                            Self::subtract(self.0[HEAD], self.lp(self.0[SHIFT])?)?,
                            width,
                        )?;
                        self.subroutine(32, head, self.0[SHIFT] + 1, 1, 6);
                    }
                }
                6 => {
                    self.pair_shift(P, 1, true)?;
                    self.0[P] |= 1;
                    self.subroutine(
                        32,
                        Self::subtract(self.0[HEAD], width)?,
                        self.0[SHIFT],
                        1,
                        7,
                    );
                }
                7 => {
                    self.0[HEAD] = Self::subtract(self.0[HEAD], width)?;
                    self.0[PC] = 5;
                }
                16 | 32 => {
                    self.0[COUNT] = 1;
                    self.address(self.0[SUBHEAD])?;
                    self.0[AR] = self.0[SUBHEAD];
                    self.0[PC] = if self.0[PC] == 16 { 17 } else { 33 };
                }
                17 => {
                    if self.0[SUBSHIFT] <= 1 {
                        self.cycle(self.0[RETURN]);
                    } else {
                        let (left, _) = self.children()?;
                        return self.compare(self.0[AR], left, 18);
                    }
                }
                18 => {
                    let (left, right) = self.children()?;
                    return if cmp >= 0 {
                        self.compare(self.0[AR], right, 19)
                    } else {
                        self.compare(left, right, 20)
                    };
                }
                19 => {
                    if cmp >= 0 {
                        self.cycle(self.0[RETURN]);
                    } else {
                        let (left, right) = self.children()?;
                        return self.compare(left, right, 20);
                    }
                }
                20 => {
                    let (left, right) = self.children()?;
                    self.0[SUBHEAD] = if cmp >= 0 { left } else { right };
                    self.0[SUBSHIFT] =
                        Self::subtract(self.0[SUBSHIFT], if cmp >= 0 { 1 } else { 2 })?;
                    self.append(self.0[SUBHEAD])?;
                    self.0[PC] = 17;
                }
                33 => {
                    if self.0[SUBP] == 1 && self.0[SUBP + 1] == 0 {
                        self.0[PC] = 38;
                    } else {
                        let stepson = Self::subtract(self.0[SUBHEAD], self.lp(self.0[SUBSHIFT])?)?;
                        return self.compare(stepson, self.0[AR], 34);
                    }
                }
                34 => {
                    if cmp <= 0 {
                        self.0[PC] = 38;
                    } else if self.0[TRUSTY] == 0 && self.0[SUBSHIFT] > 1 {
                        let (_, right) = self.children()?;
                        let stepson = Self::subtract(self.0[SUBHEAD], self.lp(self.0[SUBSHIFT])?)?;
                        return self.compare(right, stepson, 35);
                    } else {
                        self.0[PC] = 37;
                    }
                }
                35 => {
                    if cmp >= 0 {
                        self.0[PC] = 38;
                    } else {
                        let (left, _) = self.children()?;
                        let stepson = Self::subtract(self.0[SUBHEAD], self.lp(self.0[SUBSHIFT])?)?;
                        return self.compare(left, stepson, 36);
                    }
                }
                36 => {
                    self.0[PC] = if cmp >= 0 { 38 } else { 37 };
                }
                37 => {
                    let stepson = Self::subtract(self.0[SUBHEAD], self.lp(self.0[SUBSHIFT])?)?;
                    self.append(stepson)?;
                    self.0[SUBHEAD] = stepson;
                    let trail = self.trail(SUBP);
                    self.pair_shift(SUBP, trail, false)?;
                    self.0[SUBSHIFT] += trail;
                    self.0[TRUSTY] = 0;
                    self.0[PC] = 33;
                }
                38 => {
                    if self.0[TRUSTY] == 0 {
                        self.cycle(16);
                    } else {
                        self.0[PC] = self.0[RETURN];
                    }
                }
                48 => {
                    let count = self.0[COUNT] as usize;
                    if count == 0 || count > PATH || self.0[OFFSET] > width {
                        return Self::invalid();
                    }
                    if count < 2 || self.0[OFFSET] == width {
                        self.0[PC] = self.0[CYCLE_RETURN];
                        continue;
                    }
                    let len = (width - self.0[OFFSET]).min(256) as usize;
                    let work = (count + 1) * len * 2;
                    if moved + work > MAX_BYTES {
                        return Ok(YIELD);
                    }
                    // Direct/COW pages make each checked stripe non-I/O-failing;
                    // no guest callback is entered with any retained page slice.
                    let mut addresses = [0; PATH];
                    for (i, address) in addresses.iter_mut().take(count).enumerate() {
                        *address = self
                            .address(self.0[AR + i])?
                            .checked_add(self.0[OFFSET])
                            .ok_or(Error::InvalidEntry)?;
                        if !memory.native_writable_range(*address, len)? {
                            return Self::invalid();
                        }
                    }
                    let mut temp = [0; 256];
                    memory.native_read(addresses[0], &mut temp[..len])?;
                    for i in 0..count - 1 {
                        let t = memory.copy_with(
                            addresses[i],
                            addresses[i + 1],
                            len,
                            trames_native::copy,
                        )?;
                        metrics.direct_bytes_read =
                            metrics.direct_bytes_read.saturating_add(t.direct_read);
                        metrics.direct_bytes_written =
                            metrics.direct_bytes_written.saturating_add(t.direct_write);
                        metrics.bytes_read = metrics.bytes_read.saturating_add(t.direct_read);
                        metrics.bytes_written =
                            metrics.bytes_written.saturating_add(t.direct_write);
                    }
                    memory.write(addresses[count - 1], &temp[..len])?;
                    metrics.direct_bytes_read =
                        metrics.direct_bytes_read.saturating_add(len as u64);
                    metrics.direct_bytes_written =
                        metrics.direct_bytes_written.saturating_add(len as u64);
                    metrics.bytes_read = metrics.bytes_read.saturating_add(len as u64);
                    metrics.bytes_written = metrics.bytes_written.saturating_add(len as u64);
                    self.0[OFFSET] += len as u64;
                    moved += work;
                }
                FINISHED => return Ok(DONE),
                _ => return Self::invalid(),
            }
        }
        Ok(YIELD)
    }
}

pub(crate) fn step(
    memory: &mut impl NativeMemory,
    a: [u64; 3],
    metrics: &mut Metrics,
) -> Result<Return, Error> {
    let address = a[0];
    let header = memory.native_read_array::<16>(address)?;
    let kind = u64::from_le_bytes(header[8..].try_into().unwrap());
    let length = match kind {
        1 => FRAME_BYTES,
        2 => 16 * 8,
        _ => return Err(Error::InvalidEntry),
    };
    memory.check(address, length, Access::Write)?;
    if !memory.native_writable_range(address, length)? {
        // A valid guest thread can use a shared/backed stack. Choose original
        // code before array effects, just as for unsupported array backing.
        // Once progress has begun, restarting the original sort is forbidden.
        let phase_address = address.checked_add(16).ok_or(Error::InvalidEntry)?;
        if u64::from_le_bytes(header[..8].try_into().unwrap()) == VERSION
            && a[2] == 0
            && u64::from_le_bytes(memory.native_read_array(phase_address)?) == 0
        {
            return Ok(Return {
                value: 0,
                fallback: true,
            });
        }
        return Err(Error::InvalidEntry);
    }
    // Only mutable header/path words cross the boundary on each comparison.
    // Leonardo numbers are deterministic from width/count, rebuilt in native
    // registers rather than repeatedly copying the whole reserved LP table.
    let header_bytes = if kind == 1 { 24 * 8 } else { length };
    let mut bytes = [0; FRAME_BYTES];
    memory.native_read(address, &mut bytes[..header_bytes])?;
    let mut frame = Frame([0; WORDS]);
    for (value, bytes) in frame
        .0
        .iter_mut()
        .zip(bytes[..header_bytes].chunks_exact(8))
    {
        *value = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    let initial = frame.0[PC] == 0;
    let mut state_bytes = 16 + header_bytes;
    if kind == 1 && !initial {
        if frame.0[COUNT] > PATH as u64 {
            return Err(Error::InvalidEntry);
        }
        let path_bytes = frame.0[COUNT] as usize * 8;
        let path_address = address
            .checked_add((AR * 8) as u64)
            .ok_or(Error::InvalidEntry)?;
        memory.native_read(path_address, &mut bytes[AR * 8..AR * 8 + path_bytes])?;
        for (value, bytes) in frame.0[AR..]
            .iter_mut()
            .zip(bytes[AR * 8..AR * 8 + path_bytes].chunks_exact(8))
        {
            *value = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        state_bytes += path_bytes;
    }
    if kind == 1 && frame.0[WIDTH] != 0 && frame.0[NEL] >= 2 {
        if let Some(size) = frame.0[WIDTH]
            .checked_mul(frame.0[NEL])
            .filter(|&size| size <= MAX_BYTES as u64)
        {
            frame.0[LP] = frame.0[WIDTH];
            frame.0[LP + 1] = frame.0[WIDTH];
            for i in 2..96 {
                frame.0[LP + i] = frame.0[LP + i - 2]
                    .checked_add(frame.0[LP + i - 1])
                    .and_then(|v| v.checked_add(frame.0[WIDTH]))
                    .ok_or(Error::InvalidEntry)?;
                if frame.0[LP + i] >= size {
                    break;
                }
            }
        }
    }
    if frame.0[0] != VERSION || !matches!(frame.0[KIND], 1 | 2) || a[2] != 0 {
        return Err(Error::InvalidEntry);
    }
    if frame.0[PC] == 0 {
        let size = frame.0[WIDTH].checked_mul(frame.0[NEL]);
        if frame.0[KIND] == 1 {
            if frame.0[WIDTH] == 0 || frame.0[NEL] < 2 {
                frame.0[PC] = FINISHED;
            } else if size.is_none_or(|s| s > MAX_BYTES as u64) {
                return Ok(Return {
                    value: 0,
                    fallback: true,
                });
            } else {
                let size = size.unwrap();
                if !memory.native_writable_range(frame.0[BASE], size as usize)? {
                    return Ok(Return {
                        value: 0,
                        fallback: true,
                    });
                }
                frame.0[HEAD] = 0;
                frame.0[HIGH] = size - frame.0[WIDTH];
                frame.0[P] = 1;
                frame.0[P + 1] = 0;
                frame.0[SHIFT] = 1;
                frame.0[PC] = 1;
            }
            metrics.callback_sorts = metrics.callback_sorts.saturating_add(1);
        } else {
            if size.is_none() {
                return Ok(Return {
                    value: 0,
                    fallback: true,
                });
            }
            frame.0[PC] = 64;
            metrics.callback_searches = metrics.callback_searches.saturating_add(1);
        }
    }
    let cmp = a[1] as u32 as i32;
    let event = if frame.0[KIND] == 1 {
        if frame.0[PC] == FINISHED {
            DONE
        } else {
            frame.run_sort(memory, cmp, metrics)?
        }
    } else {
        match frame.0[PC] {
            65 => {
                if frame.0[NEL] == 0 {
                    return Err(Error::InvalidEntry);
                }
                if cmp == 0 {
                    frame.0[RESULT] = frame.0[RIGHT];
                    frame.0[PC] = FINISHED;
                } else {
                    let half = frame.0[NEL] / 2;
                    if cmp < 0 {
                        frame.0[NEL] = half;
                    } else {
                        frame.0[BASE] = frame.0[RIGHT]
                            .checked_add(frame.0[WIDTH])
                            .ok_or(Error::InvalidEntry)?;
                        frame.0[NEL] -= half + 1;
                    }
                    frame.0[PC] = 64;
                }
            }
            64 | FINISHED => {}
            _ => return Err(Error::InvalidEntry),
        }
        if frame.0[PC] == FINISHED {
            DONE
        } else if frame.0[NEL] == 0 {
            frame.0[RESULT] = 0;
            frame.0[PC] = FINISHED;
            DONE
        } else {
            let offset = (frame.0[NEL] / 2)
                .checked_mul(frame.0[WIDTH])
                .ok_or(Error::InvalidEntry)?;
            frame.0[LEFT] = frame.0[KEY];
            frame.0[RIGHT] = frame.0[BASE]
                .checked_add(offset)
                .ok_or(Error::InvalidEntry)?;
            frame.0[PC] = 65;
            COMPARE
        }
    };
    for (value, bytes) in frame
        .0
        .iter()
        .zip(bytes[..header_bytes].chunks_exact_mut(8))
    {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    if kind == 1 && frame.0[COUNT] > PATH as u64 {
        return Err(Error::InvalidEntry);
    }
    memory.write(address, &bytes[..header_bytes])?;
    state_bytes += header_bytes;
    if kind == 1 {
        let path_bytes = frame.0[COUNT] as usize * 8;
        for (value, bytes) in frame.0[AR..]
            .iter()
            .zip(bytes[AR * 8..AR * 8 + path_bytes].chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        memory.write(
            address
                .checked_add((AR * 8) as u64)
                .ok_or(Error::InvalidEntry)?,
            &bytes[AR * 8..AR * 8 + path_bytes],
        )?;
        state_bytes += path_bytes;
        // Initialize the reserved table once for the exact private frame ABI;
        // subsequent steps neither trust nor copy it.
        if initial {
            for (value, bytes) in frame.0[LP..AR]
                .iter()
                .zip(bytes[LP * 8..AR * 8].chunks_exact_mut(8))
            {
                bytes.copy_from_slice(&value.to_le_bytes());
            }
            memory.write(
                address
                    .checked_add((LP * 8) as u64)
                    .ok_or(Error::InvalidEntry)?,
                &bytes[LP * 8..AR * 8],
            )?;
            state_bytes += (AR - LP) * 8;
        }
    }
    metrics.callback_state_bytes = metrics
        .callback_state_bytes
        .saturating_add(state_bytes as u64);
    match event {
        COMPARE => metrics.callback_requests = metrics.callback_requests.saturating_add(1),
        YIELD => metrics.callback_yields = metrics.callback_yields.saturating_add(1),
        _ => {}
    }
    Ok(Return {
        value: event,
        fallback: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn setup(kind: u64, count: u64, width: u64) -> (Memory, Metrics) {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x4000, MAX_BYTES as u64, Permissions::RW).unwrap();
        let mut words = [0u64; WORDS];
        words[0] = VERSION;
        words[KIND] = kind;
        words[BASE] = 0x4000;
        words[NEL] = count;
        words[WIDTH] = width;
        for (i, w) in words.into_iter().enumerate() {
            m.write_array(0x1000 + i as u64 * 8, w.to_le_bytes())
                .unwrap();
        }
        (m, Metrics::default())
    }
    fn field(m: &Memory, index: usize) -> u64 {
        u64::from_le_bytes(m.read_array(0x1000 + index as u64 * 8).unwrap())
    }
    fn sort_case(count: usize, width: usize, style: usize) {
        let (mut m, mut metrics) = setup(1, count as u64, width as u64);
        let values: Vec<u64> = (0..count)
            .map(|i| match style {
                0 => i as u64,
                1 => (count - i) as u64,
                2 => ((i * 73 + 17) % 19) as u64,
                _ => ((i * 7919 + 347) % 65521) as u64,
            })
            .collect();
        let mut expected = values.clone();
        expected.sort();
        for (i, v) in values.into_iter().enumerate() {
            let mut record = vec![v as u8; width];
            record[..8].copy_from_slice(&v.to_le_bytes());
            m.write(0x4000 + (i * width) as u64, &record).unwrap();
        }
        let mut sign = 0i32;
        for _ in 0..200000 {
            let r = step(&mut m, [0x1000, sign as u64, 0], &mut metrics).unwrap();
            assert!(!r.fallback);
            if r.value == DONE {
                for (i, v) in expected.into_iter().enumerate() {
                    let mut bytes = vec![0; width];
                    m.read(0x4000 + (i * width) as u64, &mut bytes).unwrap();
                    assert_eq!(
                        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                        v,
                        "count={count} width={width} style={style}"
                    );
                    assert!(bytes[8..].iter().all(|&b| b == v as u8));
                }
                return;
            }
            if r.value == COMPARE {
                let a = u64::from_le_bytes(m.read_array(field(&m, LEFT)).unwrap());
                let b = u64::from_le_bytes(m.read_array(field(&m, RIGHT)).unwrap());
                sign = match a.cmp(&b) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
            }
        }
        panic!("did not finish");
    }
    #[test]
    fn smoothsort_preserves_records_for_small_large_equal_and_ordered_arrays() {
        for count in [0, 1, 2, 3, 15, 31, 32, 127, 256, 1024] {
            for style in 0..4 {
                sort_case(count, 8, style);
            }
        }
        for width in [9, 127, 256, 257, 4096] {
            for style in 0..4 {
                sort_case((MAX_BYTES / width).min(40), width, style);
            }
        }
    }
    #[test]
    fn malformed_continuations_reject_without_host_panics_or_large_work() {
        for phase in [
            0,
            1,
            5,
            16,
            18,
            20,
            32,
            33,
            37,
            48,
            64,
            65,
            255,
            256,
            u64::MAX,
        ] {
            for index in 0..AR + PATH {
                let (mut m, mut metrics) = setup(1, 32, 8);
                m.write_array(0x1000 + PC as u64 * 8, phase.to_le_bytes())
                    .unwrap();
                m.write_array(0x1000 + index as u64 * 8, u64::MAX.to_le_bytes())
                    .unwrap();
                let _ = step(&mut m, [0x1000, 0, 0], &mut metrics);
            }
        }
        let (mut m, mut metrics) = setup(2, 0, 8);
        m.write_array(0x1000 + PC as u64 * 8, 65u64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            step(&mut m, [0x1000, 1, 0], &mut metrics),
            Err(Error::InvalidEntry)
        ));
    }
    #[test]
    fn size_and_backing_fallback_precede_array_effects() {
        let (mut m, mut metrics) = setup(1, MAX_BYTES as u64 + 1, 8);
        m.write_array(0x4000, [17; 8]).unwrap();
        assert!(step(&mut m, [0x1000, 0, 0], &mut metrics).unwrap().fallback);
        assert_eq!(m.read_array::<8>(0x4000).unwrap(), [17; 8]);
        let (mut m, mut metrics) = setup(1, 32, 8);
        m.protect(0x4000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(step(&mut m, [0x1000, 0, 0], &mut metrics).unwrap().fallback);
        m.map_shared_anonymous(0x4000, PAGE_SIZE, Permissions::RW, true)
            .unwrap();
        assert!(step(&mut m, [0x1000, 0, 0], &mut metrics).unwrap().fallback);
        let (mut m, mut metrics) = setup(1, 32, 8);
        let frame = m.read_array::<FRAME_BYTES>(0x1000).unwrap();
        m.map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, true)
            .unwrap();
        m.write(0x1000, &frame).unwrap();
        m.write_array(0x4000, [17; 8]).unwrap();
        assert!(step(&mut m, [0x1000, 0, 0], &mut metrics).unwrap().fallback);
        assert_eq!(m.read_array::<8>(0x4000).unwrap(), [17; 8]);
        m.write_array(0x1000 + PC as u64 * 8, 1u64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            step(&mut m, [0x1000, 0, 0], &mut metrics),
            Err(Error::InvalidEntry)
        ));
        assert_eq!(m.read_array::<8>(0x4000).unwrap(), [17; 8]);
    }
}
