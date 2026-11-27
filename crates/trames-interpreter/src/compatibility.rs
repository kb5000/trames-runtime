// SPDX-License-Identifier: GPL-3.0-or-later
//! Functional compatibility for optional pointer protection. Authentication
//! and branch landing checks are disabled by project policy, not delegated to
//! host PAC keys. Branch, load and address arithmetic effects still execute.
use super::{sign_extend, Cpu, CpuFault};
use trames_memory::{CpuMemory, MemoryError};

const POINTER: u64 = (1 << 48) - 1;
impl Cpu {
    pub(super) fn execute_compatibility(
        &mut self,
        ins: u32,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<u64>, CpuFault> {
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let next = self.pc.wrapping_add(4);
        let fault = |error| CpuFault::Memory { pc: self.pc, error };
        // PACIA/B/DA/DB and AUTIA/B/DA/DB (register and zero-modifier forms).
        if ins & 0xffffe000 == 0xdac10000 || (ins & 0xffffe3e0 == 0xdac123e0) {
            return Ok(Some(next));
        }
        if matches!(ins & 0xffffffe0, 0xdac143e0 | 0xdac147e0) {
            self.set_x(rd, self.x(rd) & POINTER);
            return Ok(Some(next));
        }
        if ins & 0xffe0fc00 == 0x9ac03000 {
            self.set_x(rd, 0); // PACGA: no generic authentication code in this profile.
            return Ok(Some(next));
        }
        if matches!(
            ins & 0xfffffc00,
            0xd71f0800 | 0xd71f0c00 | 0xd73f0800 | 0xd73f0c00
        ) || matches!(
            ins & 0xfffffc1f,
            0xd61f081f | 0xd61f0c1f | 0xd63f081f | 0xd63f0c1f
        ) {
            let target = self.x(rn) & POINTER;
            if ins & (1 << 21) != 0 {
                self.set_x(30, next);
            }
            return Ok(Some(target));
        }
        if matches!(ins, 0xd65f0bff | 0xd65f0fff) {
            return Ok(Some(self.x(30) & POINTER));
        }
        if ins & 0xff200400 == 0xf8200400 {
            // LDRAA/LDRAB, signed imm10 scaled by eight, optional pre-index.
            let offset =
                sign_extend((((ins >> 12) & 511) | ((ins >> 13) & 512)) as u64, 10).wrapping_mul(8);
            let writeback = ins & 0x800 != 0;
            if writeback && rn != 31 && rn == rd {
                return Err(CpuFault::Instruction {
                    pc: self.pc,
                    instruction: ins,
                });
            }
            let address = (self.reg(rn, true) & POINTER).wrapping_add(offset);
            let value = u64::from_le_bytes(memory.read_array(address).map_err(fault)?);
            self.set_x(rd, value);
            if writeback {
                self.sp_or_x(rn, address);
            }
            return Ok(Some(next));
        }
        if matches!(
            ins & 0xffe0fc00,
            0x9ac01000 | 0x9ac01400 | 0x9ac00000 | 0xbac00000
        ) {
            let key = ins & 0xffe0fc00;
            let a = self.reg(rn, true);
            let b = self.reg(rm, key != 0x9ac01400);
            let value = match key {
                0x9ac01000 => a & POINTER, // IRG chooses the sole compatibility tag, zero.
                0x9ac01400 => self.x(rm) | (1 << ((a >> 56) & 15)),
                _ => self.arithmetic(
                    sign_extend(a & 0x00ffffffffffffff, 56),
                    sign_extend(b & 0x00ffffffffffffff, 56),
                    true,
                    key == 0xbac00000,
                    true,
                ),
            };
            self.put(rd, value, true, key == 0x9ac01000);
            return Ok(Some(next));
        }
        if matches!(ins & 0xffc0c000, 0x91800000 | 0xd1800000) {
            let offset = (((ins >> 16) & 63) as u64) * 16;
            let address = self.reg(rn, true) & POINTER;
            let value = if ins >> 30 & 1 != 0 {
                address.wrapping_sub(offset)
            } else {
                address.wrapping_add(offset)
            };
            self.put(rd, value, true, true); // ADDG/SUBG: ignore tag increment.
            return Ok(Some(next));
        }
        if matches!(ins, 0xd503207f)
            || matches!(ins & 0xffffffe0, 0xd5031000 | 0xd5031020)
            || matches!(ins, 0xd50320df | 0xd50322df | 0xd503225f | 0xd503227f)
        {
            // WFI/WFxT allow spurious wakeups; the normal scheduler still yields.
            // DGH/CLRBHB do not change architectural registers or guest memory.
            return Ok(Some(next));
        }
        // Allocation-tag loads/stores use tag zero. Zeroing and writeback are
        // real operations; ordinary mappings and permissions are still checked.
        if ins & 0xff200000 == 0xd9200000 {
            let op = (ins >> 22) & 3;
            let mode = (ins >> 10) & 3;
            let offset = sign_extend(((ins >> 12) & 511) as u64, 9).wrapping_mul(16);
            let base = self.reg(rn, true) & POINTER;
            let address = if mode == 1 {
                base
            } else {
                base.wrapping_add(offset)
            };
            if !address.is_multiple_of(16) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            if mode == 0 {
                if op == 1 {
                    // LDG
                    memory.check_translation(address).map_err(fault)?;
                    self.set_x(rd, self.x(rd) & POINTER);
                } else {
                    return Ok(None);
                } // Privileged block-tag operations remain undefined.
            } else {
                if rn != 31 && rn == rd && mode != 2 {
                    return Err(CpuFault::Instruction {
                        pc: self.pc,
                        instruction: ins,
                    });
                }
                let size = if op >= 2 { 32 } else { 16 };
                if op & 1 != 0 {
                    memory.write(address, &[0; 32][..size]).map_err(fault)?;
                } else {
                    memory
                        .check(address, size, trames_memory::Access::Write)
                        .map_err(fault)?;
                }
                if mode == 1 || mode == 3 {
                    self.sp_or_x(rn, base.wrapping_add(offset));
                }
            }
            return Ok(Some(next));
        }
        if ins & 0xfe400000 == 0x68000000 {
            // STGP stores a pair of data registers as well as an ignored tag.
            let mode = (ins >> 23) & 3;
            if mode == 0 {
                return Ok(None);
            }
            let second = ((ins >> 10) & 31) as usize;
            if mode != 2 && rn != 31 && (rn == rd || rn == second) {
                return Err(CpuFault::Instruction {
                    pc: self.pc,
                    instruction: ins,
                });
            }
            let offset = sign_extend(((ins >> 15) & 127) as u64, 7).wrapping_mul(16);
            let base = self.reg(rn, true) & POINTER;
            let address = if mode == 1 {
                base
            } else {
                base.wrapping_add(offset)
            };
            let value = self.x(rd) as u128 | (self.x(second) as u128) << 64;
            memory
                .write_array(address, value.to_le_bytes())
                .map_err(fault)?;
            if mode != 2 {
                self.sp_or_x(rn, base.wrapping_add(offset));
            }
            return Ok(Some(next));
        }
        Ok(None)
    }
}

#[cfg(test)]
use trames_memory::Memory;
#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn setup(ins: u32) -> (Cpu, Memory) {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1000, ins.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        (Cpu::new(0x1000, 0x2800), m)
    }
    #[test]
    fn disabled_authentication_and_ordering_hints_preserve_values() {
        for ins in [
            0xdac10020, 0xdac10420, 0xdac11020, 0xdac11420, 0xd50320df, 0xd50322df, 0xd503245f,
            0xd503251f,
        ] {
            let (mut c, mut m) = setup(ins);
            for i in 0..31 {
                c.set_x(i, 0xa500000000002000 + i as u64);
            }
            c.set_nzcv(11);
            c.vectors.fill(u128::MAX);
            let registers = c.registers;
            let vectors = c.vectors;
            c.step(&mut m).unwrap();
            assert_eq!(c.registers, registers);
            assert_eq!(c.vectors, vectors);
            assert_eq!(c.nzcv(), 11);
            assert_eq!(c.pc, 0x1004);
        }
    }
    #[test]
    fn authentication_is_disabled_but_branches_and_links_are_real() {
        for (ins, linked) in [
            (0xd71f0822, false),
            (0xd71f0c22, false),
            (0xd73f0822, true),
            (0xd73f0c22, true),
            (0xd61f083f, false),
            (0xd63f083f, true),
        ] {
            let (mut c, mut m) = setup(ins);
            c.set_x(1, 0x1000);
            c.set_x(30, 0x2222);
            c.step(&mut m).unwrap();
            assert_eq!(c.pc, 0x1000);
            assert_eq!(c.x(30), if linked { 0x1004 } else { 0x2222 });
        }
        let (mut c, mut m) = setup(0xd65f0bff);
        c.set_x(30, 0x1010);
        c.step(&mut m).unwrap();
        assert_eq!(c.pc, 0x1010);
    }
    #[test]
    fn authenticated_loads_have_real_offsets_and_atomic_writeback() {
        let (mut c, mut m) = setup(0xf8201c20);
        c.set_x(1, 0x2000);
        m.write_array(0x2008, 123u64.to_le_bytes()).unwrap();
        c.step(&mut m).unwrap();
        assert_eq!(c.x(0), 123);
        assert_eq!(c.x(1), 0x2008);
        let (mut c, mut m) = setup(0xf8fff420);
        c.set_x(1, 0x2008);
        m.write_array(0x2000, 321u64.to_le_bytes()).unwrap();
        c.step(&mut m).unwrap();
        assert_eq!(c.x(0), 321);
        assert_eq!(c.x(1), 0x2008);
        let (mut c, mut m) = setup(0xf8201c20);
        c.set_x(0, 123);
        c.set_x(1, 0x2ff8);
        assert!(c.step(&mut m).is_err());
        assert_eq!(c.x(0), 123);
        assert_eq!(c.x(1), 0x2ff8);
        assert_eq!(c.pc, 0x1000);
    }
    #[test]
    fn ignored_tags_still_zero_data_and_apply_writeback() {
        let (mut c, mut m) = setup(0xd9601c20);
        c.set_x(1, 0x2000);
        m.write(0x2000, &[0xff; 48]).unwrap();
        c.step(&mut m).unwrap();
        assert_eq!(c.x(1), 0x2010);
        assert_eq!(m.read_array::<16>(0x2010).unwrap(), [0; 16]);
        assert_eq!(m.read_array::<16>(0x2000).unwrap(), [0xff; 16]);
        let (mut c, mut m) = setup(0x69008820);
        c.set_x(0, 123);
        c.set_x(2, 456);
        c.set_x(1, 0x2000);
        c.step(&mut m).unwrap();
        assert_eq!(m.read_u64(0x2010).unwrap(), 123);
        assert_eq!(m.read_u64(0x2018).unwrap(), 456);
        assert_eq!(c.x(1), 0x2000);
    }
}
