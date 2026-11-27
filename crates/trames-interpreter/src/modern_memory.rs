// SPDX-License-Identifier: GPL-3.0-or-later
//! Paired LSE atomics, functional LS64 transfers and bounded MOPS operations.
use super::{Cpu, CpuFault};
use trames_memory::{CpuMemory, MemoryError, PAGE_SIZE};

const WORK_LIMIT: u64 = 64 * 1024;
fn page_remaining(address: u64, reverse: bool) -> u64 {
    if reverse {
        (address & (PAGE_SIZE - 1)) + 1
    } else {
        PAGE_SIZE - (address & (PAGE_SIZE - 1))
    }
}
impl Cpu {
    pub(super) fn execute_modern_memory(
        &mut self,
        ins: u32,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<u64>, CpuFault> {
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rs = ((ins >> 16) & 31) as usize;
        let pc = self.pc;
        let next = pc.wrapping_add(4);
        let fault = |error| CpuFault::Memory { pc, error };
        let invalid = || CpuFault::Instruction {
            pc,
            instruction: ins,
        };
        let pair = ins & 0xff20fc00;
        if matches!(pair, 0x19208000 | 0x19201000 | 0x19203000) {
            if rd == rs || rd == 31 || rs == 31 {
                return Err(invalid());
            }
            let address = self.reg(rn, true);
            if !address.is_multiple_of(16) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            // Two arbitrary registers contain both the input and the output pair.
            let input = self.x(rd) as u128 | (self.x(rs) as u128) << 64;
            if ins & (1 << 22) != 0 {
                memory.fence(std::sync::atomic::Ordering::Release);
            }
            let old = memory
                .atomic_update(address, 16, |data| {
                    let old = u128::from_le_bytes(data.try_into().unwrap());
                    let value = match pair {
                        0x19201000 => old & !input,
                        0x19203000 => old | input,
                        _ => input,
                    };
                    data.copy_from_slice(&value.to_le_bytes());
                    (old, true)
                })
                .map_err(fault)?;
            if ins & (1 << 23) != 0 {
                memory.fence(std::sync::atomic::Ordering::Acquire);
            }
            self.set_x(rd, old as u64);
            self.set_x(rs, (old >> 64) as u64);
            return Ok(Some(next));
        }
        let block = ins & 0xffe0fc00;
        if matches!(block, 0xf8209000 | 0xf820a000 | 0xf820b000 | 0xf820d000) {
            let load = block == 0xf820d000;
            let with_status = matches!(block, 0xf820a000 | 0xf820b000);
            if rd > 22 || !rd.is_multiple_of(2) || !with_status && rs != 31 {
                return Err(invalid());
            }
            let address = self.reg(rn, true);
            if !address.is_multiple_of(64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            if load {
                let bytes = memory.read_array::<64>(address).map_err(fault)?;
                for (i, part) in bytes.chunks_exact(8).enumerate() {
                    self.set_x(rd + i, u64::from_le_bytes(part.try_into().unwrap()));
                }
            } else {
                let mut bytes = [0; 64];
                for i in 0..8 {
                    bytes[i * 8..i * 8 + 8].copy_from_slice(&self.x(rd + i).to_le_bytes());
                }
                memory.write_array(address, bytes).map_err(fault)?;
                if with_status {
                    self.set_x(rs, 0);
                }
            }
            // The virtual memory fabric accepts the whole block. It does not
            // model a physical Device-memory LS64 endpoint or ACCDATA_EL1.
            return Ok(Some(next));
        }
        let key = ins & 0xff200c00;
        if !matches!(key, 0x19000400 | 0x1d000400) {
            return Ok(None);
        }
        let set = ins & 0x00c00000 == 0x00c00000;
        let tag_set = set && ins & (1 << 26) != 0;
        let stage = if set {
            (ins >> 14) & 3
        } else {
            (ins >> 22) & 3
        };
        if stage == 3
            || rd == 31
            || rn == 31
            || rd == rn
            || rs == rn
            || rs == rd
            || !set && rs == 31
        {
            return Err(invalid());
        }
        // SET accepts two option bits; COPY accepts all four temporal and
        // unprivileged hints. Ordering is already enforced by the scheduler.
        let moving = !set && ins & (1 << 26) != 0;
        let count = self.x(rn);
        if stage != 0 && count == 0 {
            return Ok(Some(next));
        }
        if stage != 0 && self.nzcv() != 0 {
            return Err(invalid());
        }
        let mut remaining = if stage == 0 {
            count.min(if moving {
                0x007fffffffffffff
            } else {
                i64::MAX as u64
            })
        } else if moving && count as i64 > 0 {
            count
        } else {
            count.wrapping_neg()
        };
        let backwards = moving
            && if stage == 0 {
                let source = self.x(rs) & 0x00ffffffffffffff;
                let dest = self.x(rd) & 0x00ffffffffffffff;
                source < dest && source.checked_add(remaining).is_some_and(|end| end > dest)
            } else {
                count as i64 > 0
            };
        if stage != 0 && !backwards && count as i64 >= 0 {
            return Err(invalid());
        }
        if stage == 2 && remaining >= PAGE_SIZE {
            return Err(invalid());
        }
        let mut dest = if stage == 0 {
            self.x(rd)
        } else if backwards {
            self.x(rd).wrapping_add(remaining).wrapping_sub(1)
        } else {
            self.x(rd).wrapping_add(count)
        };
        let mut source = if set {
            0
        } else if stage == 0 {
            self.x(rs)
        } else if backwards {
            self.x(rs).wrapping_add(remaining).wrapping_sub(1)
        } else {
            self.x(rs).wrapping_add(count)
        };
        if backwards && stage == 0 {
            dest = dest.wrapping_add(remaining).wrapping_sub(1);
            source = source.wrapping_add(remaining).wrapping_sub(1);
        }
        if tag_set && (remaining & 15 != 0 || remaining != 0 && dest & 15 != 0) {
            return Err(fault(MemoryError::Alignment(dest)));
        }
        let mut work = if stage == 0 {
            let mut work = remaining.min(page_remaining(dest, backwards));
            if !set {
                work = work.min(page_remaining(source, backwards));
            }
            work
        } else if set && stage == 1 {
            remaining & !(PAGE_SIZE - 1)
        } else {
            remaining
        };
        let mut done = 0;
        while work != 0 && (stage != 1 || set || remaining >= PAGE_SIZE) {
            if done >= WORK_LIMIT {
                self.yield_current = true;
                return Ok(Some(pc));
            }
            let mut size = work.min(page_remaining(dest, backwards));
            if !set {
                size = size.min(page_remaining(source, backwards));
            }
            let low_dest = if backwards {
                dest.wrapping_sub(size - 1)
            } else {
                dest
            };
            let low_source = if backwards {
                source.wrapping_sub(size - 1)
            } else {
                source
            };
            let mut buffer = [self.x(rs) as u8; PAGE_SIZE as usize];
            // A step fits both pages. Snapshotting the source implements the
            // overlap-safe copy direction without any unchecked guest pointer.
            if !set {
                memory
                    .read(low_source, &mut buffer[..size as usize])
                    .map_err(fault)?;
            }
            memory
                .write(low_dest, &buffer[..size as usize])
                .map_err(fault)?;
            remaining -= size;
            work -= size;
            done += size;
            if backwards {
                dest = dest.wrapping_sub(size);
                source = source.wrapping_sub(size);
            } else {
                dest = dest.wrapping_add(size);
                source = source.wrapping_add(size);
            }
            if stage == 0 && !backwards {
                self.set_x(rd, dest);
                if !set {
                    self.set_x(rs, source);
                }
                self.set_x(rn, remaining);
            } else {
                self.set_x(
                    rn,
                    if backwards {
                        remaining
                    } else {
                        remaining.wrapping_neg()
                    },
                );
            }
        }
        if stage == 0 {
            if !backwards {
                self.set_x(rd, dest.wrapping_add(remaining));
                if !set {
                    self.set_x(rs, source.wrapping_add(remaining));
                }
            }
            self.set_x(
                rn,
                if backwards {
                    remaining
                } else {
                    remaining.wrapping_neg()
                },
            );
            self.set_nzcv(0); // Option A; arithmetic flags carry stage information.
        }
        Ok(Some(next))
    }
}

#[cfg(test)]
use trames_memory::Memory;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, SliceOutcome};
    use trames_memory::Permissions;
    fn setup(words: &[u32]) -> (Cpu, Memory) {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.iter().enumerate() {
            m.write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        (Cpu::new(0x1000, 0x2800), m)
    }
    #[test]
    fn long_copy_yields_without_retiring_the_main_instruction() {
        let (mut c, mut m) = setup(&[0x19010440, 0x19410440, 0x19810440]);
        let size = 128 * 1024;
        m.map(0x2000, size, Permissions::RW).unwrap();
        m.map(0x80000, size, Permissions::RW).unwrap();
        let bytes: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
        m.write(0x80000, &bytes).unwrap();
        c.set_x(0, 0x2000);
        c.set_x(1, 0x80000);
        c.set_x(2, size);
        assert!(matches!(
            c.run_slice(&mut m, 3),
            SliceOutcome::Yield { instructions: 1 }
        ));
        assert_eq!(c.pc, 0x1004);
        assert_eq!(c.x(2), 0u64.wrapping_sub(size - PAGE_SIZE - WORK_LIMIT));
        assert!(matches!(
            c.run_slice(&mut m, 2),
            SliceOutcome::Yield { instructions: 2 }
        ));
        assert_eq!(c.pc, 0x100c);
        assert_eq!(c.x(2), 0);
        let mut output = vec![0; size as usize];
        m.read(0x2000, &mut output).unwrap();
        assert_eq!(output, bytes);
    }
    #[test]
    fn paired_atomics_snapshot_aliased_address_and_return_both_old_words() {
        let old = 0xfedcba98765432100123456789abcdefu128;
        for opcode in [0x19208000, 0x19201000, 0x19203000] {
            for ordering in [0, 1 << 22, 1 << 23, 3 << 22] {
                for base in [0, 2, 4, 31] {
                    let ins = opcode | ordering | 2 << 16 | base << 5;
                    let (mut c, mut m) = setup(&[ins]);
                    m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
                    m.write_array(0x2000, old.to_le_bytes()).unwrap();
                    c.set_x(0, 0x1122334455667788);
                    c.set_x(2, 0x99aabbccddeeff00);
                    c.put(base as usize, 0x2000, true, true);
                    let input = c.x(0) as u128 | (c.x(2) as u128) << 64;
                    let expected = match opcode {
                        0x19201000 => old & !input,
                        0x19203000 => old | input,
                        _ => input,
                    };
                    assert_eq!(c.step(&mut m).unwrap(), Event::Continue);
                    assert_eq!(c.x(0), old as u64);
                    assert_eq!(c.x(2), (old >> 64) as u64);
                    assert_eq!(u128::from_le_bytes(m.read_array(0x2000).unwrap()), expected);
                }
            }
        }
        for (first, second) in [(0, 0), (31, 2), (0, 31)] {
            let ins = 0x19208000 | second << 16 | 4 << 5 | first;
            let (mut c, mut m) = setup(&[ins]);
            assert!(matches!(c.step(&mut m), Err(CpuFault::Instruction { .. })));
        }
    }
    #[test]
    fn ls64_transfers_all_eight_words_and_snapshots_status_aliases() {
        for start in [0, 2, 14, 22] {
            for (opcode, status) in [
                (0xf83f9000, None),
                (0xf820a000, Some(start)),
                (0xf820b000, Some(31)),
            ] {
                let store = opcode | status.unwrap_or(31) << 16 | 30 << 5 | start;
                let load = 0xf83fd000 | 30 << 5 | start;
                let (mut c, mut m) = setup(&[store, load]);
                m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
                c.set_x(30, 0x2000);
                let values: [u64; 8] =
                    std::array::from_fn(|i| 0x123456789abcdef0u64.rotate_left(i as u32 * 7));
                for (i, value) in values.iter().enumerate() {
                    c.set_x(start as usize + i, *value);
                }
                assert_eq!(c.step(&mut m).unwrap(), Event::Continue);
                if let Some(status) = status {
                    assert_eq!(c.x(status as usize), 0);
                }
                for i in 0..8 {
                    c.set_x(start as usize + i, 0);
                }
                assert_eq!(c.step(&mut m).unwrap(), Event::Continue);
                for (i, value) in values.iter().enumerate() {
                    assert_eq!(c.x(start as usize + i), *value);
                }
            }
        }
    }
    #[test]
    fn paired_atomic_and_block_faults_preserve_registers_and_bytes() {
        for ins in [0x19228080, 0x19221080, 0x19223080, 0xf83f9020] {
            let (mut c, mut m) = setup(&[ins]);
            m.map(0x2000, PAGE_SIZE, Permissions::R).unwrap();
            for i in 0..31 {
                c.set_x(i, 0x2000);
            }
            c.set_x(0, 0x1234);
            c.set_x(2, 0x5678);
            let before = c.registers;
            assert!(matches!(c.step(&mut m), Err(CpuFault::Memory { .. })));
            assert_eq!(c.registers, before);
            assert_eq!(c.pc, 0x1000);
            assert_eq!(m.read_array::<64>(0x2000).unwrap(), [0; 64]);
        }
    }
    #[test]
    fn faulting_mops_can_resume_from_its_partial_progress() {
        let (mut c, mut m) = setup(&[0x19c20420, 0x19c24420, 0x19c28420]);
        m.map(0x2000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        c.set_x(0, 0x2000);
        c.set_x(1, PAGE_SIZE * 3);
        c.set_x(2, 0x5a);
        assert_eq!(c.step(&mut m).unwrap(), Event::Continue);
        assert!(matches!(c.step(&mut m), Err(CpuFault::Memory { .. })));
        assert_eq!(c.pc, 0x1004);
        assert_eq!(c.x(0), 0x5000);
        assert_eq!(c.x(1), PAGE_SIZE.wrapping_neg());
        m.map(0x4000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(c.step(&mut m).unwrap(), Event::Continue);
        assert_eq!(c.step(&mut m).unwrap(), Event::Continue);
        assert_eq!(c.x(1), 0);
        assert_eq!(m.read_array::<16>(0x4000).unwrap(), [0x5a; 16]);
    }
}
