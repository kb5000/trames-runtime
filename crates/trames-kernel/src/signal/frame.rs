// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_execution::{Aarch64State, Registers, SmeConfig, SmeState};

const FRAME_SIZE: usize = 4688;
/// A frame is serialized once, then copied page by page on the original task.
/// Its architectural changes commit only after copyout.
pub struct PreparedFrame {
    frame: FrameState,
    state: Aarch64State,
    address: u64,
    bytes: Vec<u8>,
    copied: usize,
    pub clear_sme: bool,
}
impl PreparedFrame {
    pub fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
    ) -> Result<(), trames_memory::MemoryError> {
        while self.copied < self.bytes.len() {
            let address = self
                .address
                .checked_add(self.copied as u64)
                .ok_or(trames_memory::MemoryError::InvalidRange)?;
            let count = (self.bytes.len() - self.copied)
                .min((trames_memory::PAGE_SIZE - address % trames_memory::PAGE_SIZE) as usize);
            memory.write(address, &self.bytes[self.copied..self.copied + count])?;
            self.copied += count;
        }
        Ok(())
    }
    pub(super) fn interrupted_pc(&mut self, pc: u64) {
        debug_assert_eq!(self.copied, 0);
        self.bytes[568..576].copy_from_slice(&pc.to_le_bytes());
    }
    pub fn commit(self, frame: &mut FrameState, state: &mut Aarch64State) {
        let completed = self.finish();
        *frame = completed.frame;
        *state = completed.state;
    }
    pub(super) fn finish(self) -> super::FrameCommit {
        assert_eq!(
            self.copied,
            self.bytes.len(),
            "complete original signal frame"
        );
        super::FrameCommit {
            frame: self.frame,
            state: self.state,
            clear_sme: self.clear_sme,
            restored_sme: None,
            returned: false,
        }
    }
}
pub struct FrameState {
    pub actions: Actions,
    pub mask: u64,
    pub frames: u32,
    pub alt_stack: AltStack,
}
impl Signals {
    pub fn pending_frame_state(&self) -> FrameState {
        self.frame_state()
    }
    pub fn commit_pending_frame(&mut self, frame: FrameState) {
        self.wait_mask = None;
        self.commit_frame(frame);
        self.begin_io();
    }
    pub fn commit_partial_frame(&mut self, frame: FrameState) {
        self.commit_frame(frame);
        let mut context = self.io.context.lock().unwrap();
        context.mask = self.mask;
        context.frames = self.frames;
        context.alt_stack = self.alt_stack;
    }
    #[allow(clippy::too_many_arguments)]
    pub fn enter_sme_pending(
        &mut self,
        state: &mut Aarch64State,
        memory: &mut impl CpuMemory,
        sig: u32,
        info: Info,
        action: Action,
        sme: Option<(SmeConfig, Option<&SmeState>, bool)>,
    ) -> Result<Option<trames_memory::PageFault>, Errno> {
        self.actions.accept_handler(sig, action);
        self.begin_io();
        let progress = self.io.start_frame(
            self.frame_state(),
            state,
            sig,
            info,
            action,
            sme,
            self.wait_mask,
            memory,
        );
        self.apply_pending_frame(state, progress)
    }
    pub fn resume_frame(
        &mut self,
        state: &mut Aarch64State,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<trames_memory::PageFault>, Errno> {
        let progress = self
            .io
            .resume_frame(memory)
            .expect("accepted original handler frame");
        self.apply_pending_frame(state, progress)
    }
    fn apply_pending_frame(
        &mut self,
        state: &mut Aarch64State,
        progress: super::FrameProgress,
    ) -> Result<Option<trames_memory::PageFault>, Errno> {
        match progress {
            super::FrameProgress::Complete(completed) => {
                *state = completed.state;
                self.commit_pending_frame(completed.frame);
                Ok(None)
            }
            super::FrameProgress::Page(fault) => Ok(Some(fault)),
            super::FrameProgress::EntryPage { fault, pc } => {
                state.pc = pc;
                Ok(Some(fault))
            }
            super::FrameProgress::Rseq(progress) => match progress {
                crate::rseq::ResumeProgress::Complete(pc) => {
                    state.pc = pc;
                    Ok(None)
                }
                crate::rseq::ResumeProgress::Page { fault, pc } => {
                    state.pc = pc;
                    Ok(Some(fault))
                }
                crate::rseq::ResumeProgress::Error { error, pc } => {
                    state.pc = pc;
                    self.actions.force_frame_signal(
                        &self.io,
                        None,
                        Fault {
                            signal: 11,
                            code: 128,
                            address: 0,
                        },
                    );
                    self.finish_io();
                    Err(error)
                }
            },
            super::FrameProgress::ReturnPage { fault, partial } => {
                *state = partial.state;
                self.commit_partial_frame(partial.frame);
                Ok(Some(fault))
            }
            super::FrameProgress::Error { error, signal, pc } => {
                if let Some(pc) = pc {
                    state.pc = pc;
                }
                self.actions.failed_frame(&self.io, signal);
                self.finish_io();
                Err(error)
            }
            super::FrameProgress::ReturnError {
                error,
                fault,
                partial,
            } => {
                *state = partial.state;
                self.commit_partial_frame(partial.frame);
                self.actions.force_frame_signal(&self.io, None, fault);
                self.finish_io();
                Err(error)
            }
        }
    }
    fn frame_state(&self) -> FrameState {
        FrameState {
            actions: self.actions.shared(),
            mask: self.mask,
            frames: self.frames,
            alt_stack: self.alt_stack,
        }
    }
    fn commit_frame(&mut self, frame: FrameState) {
        self.set_mask(frame.mask);
        self.frames = frame.frames;
        self.alt_stack = frame.alt_stack;
    }
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
        self.actions.accept_handler(sig, action);
        let mut frame = self.frame_state();
        let rseq = if let Some(mut resume) = self.io.rseq.begin_signal(state.pc) {
            let result = resume.progress(&self.io.rseq, memory);
            state.pc = resume.pc();
            result.map(|_| ()).map_err(|error| match error {
                crate::rseq::ResumeError::Page(_) => Errno(14),
                crate::rseq::ResumeError::Error(error) => error,
            })
        } else {
            Ok(())
        };
        let result = rseq
            .and_then(|()| {
                frame.prepare_sme_restoring(state, sig, info, action, sme, self.wait_mask)
            })
            .and_then(|mut prepared| {
                prepared.progress(memory).map_err(|_| Errno(14))?;
                prepared.commit(&mut frame, state);
                Ok(())
            });
        if let Err(error) = result {
            self.begin_io();
            self.actions.failed_frame(&self.io, sig);
            self.finish_io();
            return Err(error);
        }
        self.wait_mask = None;
        self.commit_frame(frame);
        Ok(())
    }
    pub fn restore(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
    ) -> Result<(), Errno> {
        let mut frame = self.frame_state();
        let result = frame.restore(state, memory);
        self.commit_frame(frame);
        result
    }
    pub fn restore_sme(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
        config: SmeConfig,
        sme2: bool,
    ) -> Result<Option<Box<SmeState>>, Errno> {
        let mut frame = self.frame_state();
        let result = frame.restore_sme(state, memory, config, sme2);
        self.commit_frame(frame);
        result
    }
}
impl FrameState {
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
        self.enter_sme_restoring(state, memory, sig, info, action, sme, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn enter_sme_restoring(
        &mut self,
        state: &mut Aarch64State,
        memory: &mut impl CpuMemory,
        sig: u32,
        info: Info,
        action: Action,
        sme: Option<(SmeConfig, Option<&SmeState>, bool)>,
        restore_mask: Option<u64>,
    ) -> Result<(), Errno> {
        self.actions.accept_handler(sig, action);
        let mut prepared =
            self.prepare_sme_restoring(state, sig, info, action, sme, restore_mask)?;
        prepared.progress(memory).map_err(|_| Errno(14))?;
        prepared.commit(self, state);
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_sme_restoring(
        &self,
        state: &Aarch64State,
        sig: u32,
        info: Info,
        action: Action,
        sme: Option<(SmeConfig, Option<&SmeState>, bool)>,
        restore_mask: Option<u64>,
    ) -> Result<PreparedFrame, Errno> {
        let mut state = state.clone();
        let mut next = FrameState {
            actions: self.actions.shared(),
            mask: self.mask,
            frames: self.frames,
            alt_stack: self.alt_stack,
        };
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
        if !(1..=64).contains(&sig) {
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
        let mut frame = vec![0; size];
        write_siginfo(&mut frame[..128], sig, info);
        frame[144..152].copy_from_slice(&old_alt.sp.to_le_bytes());
        frame[152..156].copy_from_slice(&old_alt.reported_flags(state.sp).to_le_bytes());
        frame[160..168].copy_from_slice(&old_alt.size.to_le_bytes());
        frame[168..176].copy_from_slice(&restore_mask.unwrap_or(self.mask).to_le_bytes());
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
        if sme.is_some() {
            state.tpidr2_el0 = 0;
        }
        if old_alt.flags & SS_AUTODISARM != 0 {
            next.alt_stack = AltStack::default();
        }
        next.mask |= action.mask;
        if action.flags & 0x40000000 == 0 {
            next.mask |= 1u64 << (sig - 1);
        }
        next.mask &= !UNBLOCKABLE;
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
        next.frames = next.frames.saturating_add(1);
        Ok(PreparedFrame {
            frame: next,
            state,
            address: sp,
            bytes: frame,
            copied: 0,
            clear_sme: sme.is_some(),
        })
    }
    pub(super) fn validate_return_address(sp: u64) -> Result<(), Errno> {
        let address = sp & 0x00ff_ffff_ffff_ffff;
        if sp & 15 != 0
            || address
                .checked_add(FRAME_SIZE as u64)
                .is_none_or(|end| end > trames_memory::ADDRESS_LIMIT)
        {
            return Err(Errno(14));
        }
        Ok(())
    }
    pub fn restore_sme(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
        config: SmeConfig,
        sme2: bool,
    ) -> Result<Option<Box<SmeState>>, Errno> {
        let address = state.sp;
        Self::restore_scalar(self, state, memory, address)?;
        let registers = self.restore_floating(state, memory, address, Some(config), sme2)?;
        self.restore_stack(state, memory, address)?;
        Ok(registers.flatten())
    }
    pub fn restore(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
    ) -> Result<(), Errno> {
        let address = state.sp;
        Self::restore_scalar(self, state, memory, address)?;
        self.restore_floating(state, memory, address, None, false)?;
        self.restore_stack(state, memory, address)
    }
    fn restore_scalar(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
        address: u64,
    ) -> Result<(), Errno> {
        super::return_gprs::Gprs::new(address)
            .progress(self, state, None, memory)
            .map_err(|error| match error {
                crate::user_copy::CopyError::Page(_) => Errno(14),
                crate::user_copy::CopyError::Error(error) => error,
            })
    }
    fn restore_floating(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
        address: u64,
        config: Option<SmeConfig>,
        sme2: bool,
    ) -> Result<Option<Option<Box<SmeState>>>, Errno> {
        let mut floating = super::return_fp::Floating::new(address, config, sme2, None);
        floating
            .progress(state, memory)
            .map_err(|error| match error {
                crate::user_copy::CopyError::Page(_) => Errno(14),
                crate::user_copy::CopyError::Error(error) => error,
            })?;
        Ok(floating.take_result())
    }
    pub(super) fn restore_stack(
        &mut self,
        state: &Aarch64State,
        memory: &impl CpuMemory,
        address: u64,
    ) -> Result<(), Errno> {
        let saved_alt = AltStack::read(memory, address + 144)?;
        let _ = self.alt_stack.exchange(state.sp, Some(saved_alt));
        self.frames = self.frames.saturating_sub(1);
        Ok(())
    }
}

pub(super) const SVE_MAGIC: u32 = 0x53564501;
pub(super) const ZA_MAGIC: u32 = 0x54366345;
pub(super) const ZT_MAGIC: u32 = 0x5a544e01;
pub(super) const TPIDR2_MAGIC: u32 = 0x54504902;
pub(super) const EXTRA_MAGIC: u32 = 0x45585401;
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
    fn sme_frame_failure_keeps_prior_native_restore_stages() {
        for bad in 0..3 {
            let (mut signals, mut memory, mut state, registers) = setup(3);
            enter(&mut signals, &mut memory, &mut state, &registers);
            let frame = state.sp;
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
            assert!(signals
                .restore_sme(&mut state, &memory, SmeConfig::default(), true)
                .is_err());
            assert_eq!(state.pc, 0x4000);
            assert_eq!(state.sp, 0x30000);
            assert_ne!(state.sp, frame);
            // Bad SVE metadata and bad EXTRA fail before FPSIMD/TPIDR2;
            // bad ZA VL is checked after both have already committed.
            assert_eq!(state.tpidr2_el0, if bad == 2 { 0x713 } else { 0 });
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
        assert!(signals
            .restore_sme(&mut state, &memory, SmeConfig::default(), true)
            .unwrap()
            .is_none());
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
        assert!(signals
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
            .is_err());
        assert_eq!(state, saved);
        assert_eq!(signals.frames, 0);
    }
}
