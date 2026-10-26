// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_execution::{Aarch64State, Registers};

const FRAME_SIZE: usize = 4688;
impl Signals {
    /// Publish a complete signal frame before changing architectural/task state.
    pub fn enter(
        &mut self,
        state: &mut Aarch64State,
        memory: &mut impl CpuMemory,
        sig: u32,
        info: Info,
        action: Action,
    ) -> Result<(), Errno> {
        if self.frames >= 8 || !(1..=64).contains(&sig) {
            return Err(Errno(14));
        }
        let old_alt = self.alt_stack;
        let use_alt = action.flags & 0x08000000 != 0
            && old_alt.flags & SS_DISABLE == 0
            && !old_alt.on_stack(state.sp);
        let top = if use_alt {
            old_alt.sp.checked_add(old_alt.size).ok_or(Errno(14))?
        } else {
            state.sp
        };
        let sp = top.checked_sub(FRAME_SIZE as u64).ok_or(Errno(14))? & !15;
        if (use_alt || old_alt.contains(state.sp)) && sp < old_alt.sp {
            return Err(Errno(14));
        }
        memory
            .check(sp, FRAME_SIZE, Access::Write)
            .map_err(|_| Errno(14))?;
        let mut frame = vec![0; FRAME_SIZE];
        write_siginfo(&mut frame[..128], sig, info);
        frame[144..152].copy_from_slice(&old_alt.sp.to_le_bytes());
        frame[152..156].copy_from_slice(&old_alt.reported_flags(state.sp).to_le_bytes());
        frame[160..168].copy_from_slice(&old_alt.size.to_le_bytes());
        frame[168..176].copy_from_slice(&self.mask.to_le_bytes());
        frame[304..312].copy_from_slice(&info.fault.unwrap_or(0).to_le_bytes());
        for r in 0..31 {
            frame[312 + r * 8..320 + r * 8].copy_from_slice(&state.x(r).to_le_bytes());
        }
        frame[560..568].copy_from_slice(&state.sp.to_le_bytes());
        frame[568..576].copy_from_slice(&state.pc.to_le_bytes());
        frame[576..584].copy_from_slice(&(state.nzcv as u64).to_le_bytes());
        frame[592..596].copy_from_slice(&0x46508001u32.to_le_bytes());
        frame[596..600].copy_from_slice(&528u32.to_le_bytes());
        frame[600..604].copy_from_slice(&state.fpsr.to_le_bytes());
        frame[604..608].copy_from_slice(&state.fpcr.to_le_bytes());
        for r in 0..32 {
            frame[608 + r * 16..624 + r * 16].copy_from_slice(&state.vectors[r].to_le_bytes());
        }
        memory.write(sp, &frame).map_err(|_| Errno(14))?;
        if old_alt.flags & SS_AUTODISARM != 0 {
            self.alt_stack = AltStack::default();
        }
        self.mask |= action.mask;
        if action.flags & 0x40000000 == 0 {
            self.mask |= 1u64 << (sig - 1);
        }
        self.mask &= !UNBLOCKABLE;
        if action.flags & 0x80000000 != 0 {
            self.actions.set(sig as usize, Action::default());
        }
        state.set_x(0, sig as u64);
        state.set_x(1, sp);
        state.set_x(2, sp + 128);
        state.set_x(
            30,
            if action.flags & 0x04000000 == 0 {
                0x7fff_ffd0_0000
            } else {
                action.restorer
            },
        );
        state.sp = sp;
        state.pc = action.handler;
        self.frames += 1;
        Ok(())
    }
    /// Decode and validate the complete frame before restoring registers. TLS
    /// is not part of Linux's signal frame and remains the current task's TLS.
    pub fn restore(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
    ) -> Result<(), Errno> {
        if self.frames == 0 {
            return Err(Errno(14));
        }
        let sp = state.sp;
        memory
            .check(sp, FRAME_SIZE, Access::Read)
            .map_err(|_| Errno(14))?;
        let mut frame = vec![0; FRAME_SIZE];
        memory.read(sp, &mut frame).map_err(|_| Errno(14))?;
        let word = |i| u64::from_le_bytes(frame[i..i + 8].try_into().unwrap());
        let field = |i| u32::from_le_bytes(frame[i..i + 4].try_into().unwrap());
        let new_sp = word(560);
        let new_pc = word(568);
        // Interrupted leaf assembly need not have a call-boundary aligned SP.
        if new_sp >= 1 << 48
            || new_pc & 3 != 0
            || new_pc >= 1 << 48
            || field(592) != 0x46508001
            || field(596) != 528
        {
            return Err(Errno(14));
        }
        let restored_alt = AltStack::restore(memory, sp + 144)?;
        for r in 0..31 {
            state.set_x(r, word(312 + r * 8));
        }
        state.sp = new_sp;
        state.pc = new_pc;
        state.nzcv = (word(576) as u32) & 0xf0000000;
        state.fpsr = field(600) & 0x0800009f;
        state.fpcr = field(604) & 0x03c00000;
        for r in 0..32 {
            state.vectors[r] =
                u128::from_le_bytes(frame[608 + r * 16..624 + r * 16].try_into().unwrap());
        }
        self.mask = word(168) & !UNBLOCKABLE;
        self.alt_stack = restored_alt;
        self.frames -= 1;
        Ok(())
    }
}
