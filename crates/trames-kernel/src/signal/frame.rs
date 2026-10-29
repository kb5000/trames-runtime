// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_execution::{Aarch64State, Registers, SmeConfig, SmeState};

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
        self.enter_sme(state, memory, sig, info, action, None)
    }
    pub fn enter_sme(
        &mut self,
        state: &mut Aarch64State,
        memory: &mut impl CpuMemory,
        sig: u32,
        info: Info,
        action: Action,
        sme: Option<(SmeConfig, Option<&SmeState>, bool)>,
    ) -> Result<(), Errno> {
        let records = sme.map(|(config, registers, sme2)| {
            sme_records(config, registers, sme2, state.tpidr2_el0)
        });
        let extra = records
            .as_ref()
            .is_some_and(|r| 1120 + r.len() > FRAME_SIZE);
        let start = if extra { 1168 } else { 1120 };
        let size = records
            .as_ref()
            .map_or(FRAME_SIZE, |r| FRAME_SIZE.max(start + r.len()));
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
        let sp = top.checked_sub(size as u64).ok_or(Errno(14))? & !15;
        if (use_alt || old_alt.contains(state.sp)) && sp < old_alt.sp {
            return Err(Errno(14));
        }
        memory
            .check(sp, size, Access::Write)
            .map_err(|_| Errno(14))?;
        let mut frame = vec![0; size];
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
        if let Some(records) = records {
            if extra {
                header(&mut frame[1120..], EXTRA_MAGIC, 32);
                frame[1128..1136].copy_from_slice(&(sp + start as u64).to_le_bytes());
                frame[1136..1140].copy_from_slice(&(records.len() as u32).to_le_bytes());
            }
            frame[start..start + records.len()].copy_from_slice(&records);
        }
        memory.write(sp, &frame).map_err(|_| Errno(14))?;
        if sme.is_some() {
            state.tpidr2_el0 = 0;
        }
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
    /// Validate optional extension records before the existing atomic base
    /// restore. The bounded context profile caps even guest-edited extra data.
    pub fn restore_sme(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
        config: SmeConfig,
        sme2: bool,
    ) -> Result<Option<Box<SmeState>>, Errno> {
        let (mut registers, tpidr2) = read_sme_records(memory, state.sp, config, sme2)?;
        self.restore(state, memory)?;
        state.tpidr2_el0 = tpidr2;
        if let Some(registers) = registers.as_mut().filter(|r| r.svcr & 1 != 0) {
            for (index, vector) in state.vectors.iter().enumerate() {
                let offset = index * config.vl as usize;
                registers.z[offset..offset + 16].copy_from_slice(&vector.to_le_bytes());
            }
        }
        Ok(registers)
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

const SVE_MAGIC: u32 = 0x53564501;
const ZA_MAGIC: u32 = 0x54366345;
const ZT_MAGIC: u32 = 0x5a544e01;
const TPIDR2_MAGIC: u32 = 0x54504902;
const EXTRA_MAGIC: u32 = 0x45585401;
fn aligned(n: usize) -> usize {
    (n + 15) & !15
}
fn header(out: &mut [u8], magic: u32, size: usize) {
    out[..4].copy_from_slice(&magic.to_le_bytes());
    out[4..8].copy_from_slice(&(size as u32).to_le_bytes());
}
fn record(out: &mut Vec<u8>, magic: u32, size: usize) -> &mut [u8] {
    let start = out.len();
    out.resize(start + aligned(size), 0);
    header(&mut out[start..], magic, aligned(size));
    &mut out[start..]
}
fn sme_records(
    config: SmeConfig,
    registers: Option<&SmeState>,
    sme2: bool,
    tpidr2: u64,
) -> Vec<u8> {
    let vl = config.vl as usize;
    let mut out = Vec::new();
    let tls = record(&mut out, TPIDR2_MAGIC, 16);
    tls[8..16].copy_from_slice(&tpidr2.to_le_bytes());
    if let Some(r) = registers.filter(|r| r.svcr & 1 != 0) {
        let n = vl * 32;
        let predicates = vl / 8 * 16;
        let sve = record(&mut out, SVE_MAGIC, 16 + n + predicates + vl / 8);
        sve[8..10].copy_from_slice(&config.vl.to_le_bytes());
        sve[10..12].copy_from_slice(&1u16.to_le_bytes());
        sve[16..16 + n].copy_from_slice(&r.z[..n]);
        sve[16 + n..16 + n + predicates].copy_from_slice(&r.p[..predicates]);
        // Streaming FFR is unavailable without FA64 and remains zero.
    }
    let active = registers.filter(|r| r.svcr & 2 != 0);
    let za = record(&mut out, ZA_MAGIC, 16 + active.map_or(0, |_| vl * vl));
    za[8..10].copy_from_slice(&config.vl.to_le_bytes());
    if let Some(r) = active {
        za[16..16 + vl * vl].copy_from_slice(&r.za[..vl * vl]);
        if sme2 {
            let zt = record(&mut out, ZT_MAGIC, 80);
            zt[8..10].copy_from_slice(&1u16.to_le_bytes());
            zt[16..80].copy_from_slice(&r.zt);
        }
    }
    out.resize(out.len() + 16, 0);
    out
}
fn read_sme_records(
    memory: &impl CpuMemory,
    sp: u64,
    config: SmeConfig,
    sme2: bool,
) -> Result<(Option<Box<SmeState>>, u64), Errno> {
    let mut registers = Box::new(SmeState {
        vl: config.vl as u64,
        ..Default::default()
    });
    let mut data = vec![0; 4096];
    memory
        .read(sp.checked_add(592).ok_or(Errno(14))?, &mut data)
        .map_err(|_| Errno(14))?;
    let vl = config.vl as usize;
    let mut offset = 0;
    let mut seen = 0u32;
    let mut extra = false;
    let mut tpidr2 = 0;
    loop {
        if offset + 8 > data.len() {
            return Err(Errno(14));
        }
        let field = |i| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let magic = field(offset);
        let size = field(offset + 4) as usize;
        if magic == 0 && size == 0 {
            break;
        }
        if size < 16 || size % 16 != 0 || size > data.len() - offset {
            return Err(Errno(14));
        }
        let d = &data[offset..offset + size];
        let bit = match magic {
            0x46508001 => 1,
            SVE_MAGIC => 2,
            ZA_MAGIC => 4,
            ZT_MAGIC => 8,
            TPIDR2_MAGIC => 16,
            EXTRA_MAGIC => 32,
            0x45535201 => 64,
            _ => return Err(Errno(14)),
        };
        if seen & bit != 0 {
            return Err(Errno(14));
        }
        seen |= bit;
        let half = |i| u16::from_le_bytes(d[i..i + 2].try_into().unwrap()) as usize;
        match magic {
            0x46508001 if size != 528 || extra => return Err(Errno(14)),
            0x45535201 if size != 16 || extra => return Err(Errno(14)),
            TPIDR2_MAGIC => {
                if size != 16 {
                    return Err(Errno(14));
                }
                tpidr2 = u64::from_le_bytes(d[8..16].try_into().unwrap());
            }
            SVE_MAGIC => {
                if half(8) != vl || half(10) & !1 != 0 {
                    return Err(Errno(14));
                }
                if size != 16 {
                    let n = vl * 32;
                    let predicates = vl / 8 * 16;
                    if half(10) != 1 || size != aligned(16 + n + predicates + vl / 8) {
                        return Err(Errno(14));
                    }
                    registers.svcr |= 1;
                    registers.z[..n].copy_from_slice(&d[16..16 + n]);
                    registers.p[..predicates].copy_from_slice(&d[16 + n..16 + n + predicates]);
                }
            }
            ZA_MAGIC => {
                if half(8) != vl || size != 16 && size != 16 + vl * vl {
                    return Err(Errno(14));
                }
                if size > 16 {
                    registers.svcr |= 2;
                    registers.za[..vl * vl].copy_from_slice(&d[16..]);
                }
            }
            ZT_MAGIC => {
                if !sme2 || size != 80 || half(8) != 1 {
                    return Err(Errno(14));
                }
                registers.zt.copy_from_slice(&d[16..80]);
            }
            EXTRA_MAGIC => {
                if extra
                    || size != 32
                    || offset + 48 > data.len()
                    || data[offset + 32..offset + 40] != [0; 8]
                {
                    return Err(Errno(14));
                }
                let address = u64::from_le_bytes(d[8..16].try_into().unwrap());
                let bytes = u32::from_le_bytes(d[16..20].try_into().unwrap()) as usize;
                if address
                    != sp
                        .checked_add((592 + offset + 48) as u64)
                        .ok_or(Errno(14))?
                    || bytes < 16
                    || bytes > 8192
                    || bytes % 16 != 0
                {
                    return Err(Errno(14));
                }
                data.resize(bytes, 0);
                memory.read(address, &mut data).map_err(|_| Errno(14))?;
                extra = true;
                offset = 0;
                continue;
            }
            _ => {}
        }
        offset += size;
    }
    if seen & 1 == 0 || seen & 8 != 0 && registers.svcr & 2 == 0 {
        return Err(Errno(14));
    }
    Ok(((registers.svcr != 0).then_some(registers), tpidr2))
}

#[cfg(test)]
mod sme_tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    fn setup(svcr: u64) -> (Signals, Memory, Aarch64State, SmeState) {
        let mut memory = Memory::default();
        memory.map(0x10000, 0x20000, Permissions::RW).unwrap();
        let state = Aarch64State {
            pc: 0x4000,
            sp: 0x30000,
            tpidr2_el0: 0x713,
            vectors: [0x3713; 32],
            ..Default::default()
        };
        let registers = SmeState {
            svcr,
            z: [0x5a; 2048],
            p: [0x11; 128],
            za: [0xc7; 4096],
            zt: [0xa7; 64],
            ..Default::default()
        };
        (Signals::default(), memory, state, registers)
    }
    fn enter(
        signals: &mut Signals,
        memory: &mut Memory,
        state: &mut Aarch64State,
        registers: &SmeState,
    ) {
        signals
            .enter_sme(
                state,
                memory,
                10,
                Info::default(),
                Action {
                    handler: 0x5000,
                    ..Default::default()
                },
                Some((SmeConfig::default(), Some(registers), true)),
            )
            .unwrap();
    }
    #[test]
    fn live_sme_signal_uses_contiguous_extra_context_and_restores_all_state() {
        let (mut signals, mut memory, mut state, registers) = setup(3);
        let saved = state.clone();
        enter(&mut signals, &mut memory, &mut state, &registers);
        assert_eq!(state.tpidr2_el0, 0);
        assert_eq!(state.pc, 0x5000);
        assert_eq!(
            memory.read_array::<4>(state.sp + 1120).unwrap(),
            EXTRA_MAGIC.to_le_bytes()
        );
        assert_eq!(memory.read_u64(state.sp + 1128).unwrap(), state.sp + 1168);
        let r = signals
            .restore_sme(&mut state, &memory, SmeConfig::default(), true)
            .unwrap()
            .unwrap();
        assert_eq!(state, saved);
        assert_eq!(signals.frames, 0);
        assert_eq!(r.svcr, 3);
        assert_eq!(r.za, registers.za);
        assert_eq!(r.zt, registers.zt);
        assert_eq!(r.p, registers.p);
        for (i, z) in r.z.chunks_exact(64).enumerate() {
            assert_eq!(&z[..16], &saved.vectors[i].to_le_bytes());
            assert_eq!(&z[16..], &[0x5a; 48]);
        }
    }
    #[test]
    fn sme_frame_validation_is_atomic_for_bad_vl_extra_and_zt() {
        for bad in 0..3 {
            let (mut signals, mut memory, mut state, registers) = setup(3);
            enter(&mut signals, &mut memory, &mut state, &registers);
            let saved = state.clone();
            match bad {
                0 => memory
                    .write_array(state.sp + 1168 + 16 + 8, 32u16.to_le_bytes())
                    .unwrap(),
                1 => memory
                    .write_array(state.sp + 1128, (state.sp + 1184).to_le_bytes())
                    .unwrap(),
                _ => memory
                    .write_array(state.sp + 1168 + 16 + 2208 + 8, 32u16.to_le_bytes())
                    .unwrap(),
            }
            assert!(
                signals
                    .restore_sme(&mut state, &memory, SmeConfig::default(), true)
                    .is_err()
            );
            assert_eq!(state, saved);
            assert_eq!(signals.frames, 1);
        }
    }
    #[test]
    fn nonstreaming_sme_signal_keeps_baseline_frame_size_and_nested_tls() {
        let (mut signals, mut memory, mut state, _) = setup(0);
        let saved = state.clone();
        signals
            .enter_sme(
                &mut state,
                &mut memory,
                10,
                Info::default(),
                Action {
                    handler: 0x5000,
                    ..Default::default()
                },
                Some((SmeConfig::default(), None, true)),
            )
            .unwrap();
        assert_eq!(state.sp, saved.sp - FRAME_SIZE as u64);
        assert_eq!(state.tpidr2_el0, 0);
        assert!(
            signals
                .restore_sme(&mut state, &memory, SmeConfig::default(), true)
                .unwrap()
                .is_none()
        );
        assert_eq!(state, saved);
    }
    #[test]
    fn too_small_altstack_does_not_partially_deliver_sme_signal() {
        let (mut signals, mut memory, mut state, registers) = setup(3);
        let saved = state.clone();
        signals.alt_stack = AltStack {
            sp: 0x10000,
            size: 5000,
            flags: 0,
        };
        assert!(
            signals
                .enter_sme(
                    &mut state,
                    &mut memory,
                    10,
                    Info::default(),
                    Action {
                        handler: 0x5000,
                        flags: 0x08000000,
                        ..Default::default()
                    },
                    Some((SmeConfig::default(), Some(&registers), true))
                )
                .is_err()
        );
        assert_eq!(state, saved);
        assert_eq!(signals.frames, 0);
    }
}
