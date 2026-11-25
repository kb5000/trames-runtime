// SPDX-License-Identifier: GPL-3.0-or-later
use super::frame::{EXTRA_MAGIC, TPIDR2_MAGIC, ZA_MAGIC};
use super::*;
use std::{cell::RefCell, sync::Arc};
use trames_execution::{Aarch64State, SmeConfig, SmeState};
use trames_memory::{Access, Memory, MemoryError, PageWait, Permissions, PAGE_SIZE};

// Selected accesses model a mapping becoming unavailable between native
// get_user calls, without blocking earlier reads from the same page.
struct Reads {
    memory: Memory,
    permanent: Option<u64>,
    waiting: Option<u64>,
    writing: Option<u64>,
    wait: Arc<PageWait>,
    calls: RefCell<Vec<u64>>,
}
impl CpuMemory for Reads {
    fn mapped_at_or_after(&self, a: u64) -> bool {
        self.memory.mapped_at_or_after(a)
    }
    fn async_faults_possible(&self) -> bool {
        true
    }
    fn read(&self, a: u64, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.calls.borrow_mut().push(a);
        if self.permanent == Some(a) {
            return Err(MemoryError::InvalidRange);
        }
        if self.waiting == Some(a) && !self.wait.ready() {
            return Err(self.wait.fault(a));
        }
        self.memory.read(a, bytes)
    }
    fn write(&mut self, a: u64, b: &[u8]) -> Result<(), MemoryError> {
        if self.writing == Some(a) && !self.wait.ready() {
            return Err(self.wait.fault(a));
        }
        self.memory.write(a, b)
    }
    fn check(&self, a: u64, n: usize, access: Access) -> Result<(), MemoryError> {
        self.memory.check(a, n, access)
    }
    fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
        self.memory.check_translation(a)
    }
    fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
        self.memory.fetch_u32(a)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(a)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!()
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!()
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!()
    }
}
const FRAME: u64 = 0x10000;
fn fixture() -> (Signals, Reads, Aarch64State, Aarch64State) {
    let mut signals = Signals {
        mask: 1 << 4,
        ..Default::default()
    };
    let mut memory = Memory::default();
    memory.map(0x1000, 0x70000, Permissions::RW).unwrap();
    let mut state = Aarch64State {
        sp: FRAME + 4688,
        pc: 0x4000,
        vectors: [0x3713; 32],
        tpidr2_el0: 0x713,
        ..Default::default()
    };
    for (index, value) in state.registers.iter_mut().enumerate() {
        *value = 37 + index as u64;
    }
    let saved = state.clone();
    signals
        .enter(
            &mut state,
            &mut memory,
            10,
            Info::default(),
            Action {
                handler: 0x5000,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(state.sp, FRAME);
    state.vectors.fill(0xabcdef);
    signals.begin_io();
    (
        signals,
        Reads {
            memory,
            permanent: None,
            waiting: None,
            writing: None,
            wait: Arc::default(),
            calls: RefCell::default(),
        },
        state,
        saved,
    )
}
fn record(memory: &mut Memory, address: u64, magic: u32, size: u32) {
    memory.write_array(address, magic.to_le_bytes()).unwrap();
    memory.write_array(address + 4, size.to_le_bytes()).unwrap();
}
#[test]
fn failed_scalar_is_zeroed_later_scalars_still_restore_and_mask_survives() {
    let (signals, mut memory, state, saved) = fixture();
    memory.permanent = Some(FRAME + 320);
    memory.waiting = Some(FRAME + 328);
    let task = &signals.io;
    let FrameProgress::ReturnPage { partial, .. } = task.start_frame_return(
        signals.pending_frame_state(),
        state,
        None,
        false,
        None,
        &mut memory,
    ) else {
        panic!("later scalar must wait");
    };
    assert_eq!(&partial.state.registers[..2], &[37, 0]);
    assert_eq!(task.mask(), signals.mask & !(1 << 9));
    memory
        .memory
        .write_array(FRAME + 312, 99u64.to_le_bytes())
        .unwrap();
    memory.permanent = None;
    memory.wait.finish();
    let Some(FrameProgress::ReturnError {
        partial,
        error: Errno(14),
        fault,
    }) = task.resume_frame(&mut memory)
    else {
        panic!("accepted scalar failure cannot be repaired retroactively");
    };
    assert_eq!(partial.state.registers[0], 37);
    assert_eq!(partial.state.registers[1], 0);
    assert_eq!(&partial.state.registers[2..], &saved.registers[2..]);
    assert_eq!((partial.state.sp, partial.state.pc), (saved.sp, saved.pc));
    assert_eq!(fault.address, saved.sp);
    assert!(
        !memory.calls.borrow().contains(&(FRAME + 592)),
        "scalar failure skips optional record parsing"
    );
}
#[test]
fn failed_sp_restore_reports_zero_after_restoring_later_scalars() {
    let (signals, mut memory, state, saved) = fixture();
    memory.permanent = Some(FRAME + 560);
    let FrameProgress::ReturnError {
        partial,
        error: Errno(14),
        fault,
    } = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        None,
        false,
        None,
        &mut memory,
    )
    else {
        panic!("failed SP get_user must finish the remaining scalar restores");
    };
    assert_eq!(partial.state.sp, 0);
    assert_eq!(partial.state.pc, saved.pc);
    assert_eq!(partial.state.registers, saved.registers);
    assert_eq!(partial.frame.mask, 1 << 4);
    assert_eq!(fault.address, 0);
    assert!(memory.calls.borrow().contains(&(FRAME + 576)));
}

#[test]
fn invalid_pstate_keeps_registers_and_validates_modes_without_prevalidating_pc_or_sp() {
    for invalid in [1u64, 16, 64, 128, 256, 512] {
        let (signals, mut memory, state, saved) = fixture();
        memory
            .memory
            .write_array(FRAME + 576, (invalid | 0xa0000000).to_le_bytes())
            .unwrap();
        let FrameProgress::ReturnError { partial, .. } = signals.io.start_frame_return(
            signals.pending_frame_state(),
            state,
            None,
            false,
            None,
            &mut memory,
        ) else {
            panic!("non-EL0t or interrupt masks must fail");
        };
        assert_eq!((partial.state.sp, partial.state.pc), (saved.sp, saved.pc));
        assert_eq!(partial.state.nzcv, 0xa0000000);
    }
    let (signals, mut memory, state, _) = fixture();
    memory
        .memory
        .write_array(FRAME + 560, u64::MAX.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(FRAME + 568, 0x4001u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(FRAME + 576, 0xffff_ffff_a000_0020u64.to_le_bytes())
        .unwrap();
    let FrameProgress::Complete(done) = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        None,
        false,
        None,
        &mut memory,
    ) else {
        panic!("EL0 access/fetch handles invalid restored PC/SP");
    };
    assert_eq!((done.state.sp, done.state.pc), (u64::MAX, 0x4001));
    assert_eq!(
        done.state.nzcv, 0xa0000000,
        "RES0 bits are ignored before validating EL0t"
    );
}
#[test]
fn permanent_fp_payload_error_survives_a_later_scalar_wait_and_keeps_old_vectors() {
    let (signals, mut memory, state, saved) = fixture();
    let vectors = state.vectors;
    memory.permanent = Some(FRAME + 608);
    memory.waiting = Some(FRAME + 600);
    let FrameProgress::ReturnPage { partial, .. } = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        None,
        false,
        None,
        &mut memory,
    ) else {
        panic!("FPSR must still be accessed after vector copy failure");
    };
    assert_eq!(partial.state.vectors, vectors);
    assert_eq!(partial.state.pc, saved.pc);
    memory.permanent = None;
    memory.wait.finish();
    let Some(FrameProgress::ReturnError {
        partial,
        error: Errno(14),
        ..
    }) = signals.io.resume_frame(&mut memory)
    else {
        panic!("original FP copy failed");
    };
    assert_eq!(partial.state.vectors, vectors);
    assert!(
        memory.calls.borrow().contains(&(FRAME + 604)),
        "FPCR follows FPSR even after vector failure"
    );
}
#[test]
fn accepted_fp_state_is_published_before_altstack_wait_and_is_never_reloaded() {
    let (signals, mut memory, state, saved) = fixture();
    memory.waiting = Some(FRAME + 144);
    let FrameProgress::ReturnPage { partial, .. } = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        None,
        false,
        None,
        &mut memory,
    ) else {
        panic!("altstack comes after FP");
    };
    assert_eq!(partial.state.vectors, saved.vectors);
    memory
        .memory
        .write_array(FRAME + 608, 0x99u128.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    let Some(FrameProgress::Complete(done)) = signals.io.resume_frame(&mut memory) else {
        panic!("original stack restore");
    };
    assert_eq!(done.state.vectors, saved.vectors);
}
#[test]
fn descriptor_walk_accepts_relocated_fp_repeated_esr_and_unmapped_unused_tail() {
    let (signals, mut memory, state, saved) = fixture();
    let fp = memory.memory.read_array::<528>(FRAME + 592).unwrap();
    record(&mut memory.memory, FRAME + 592, 0x45535201, 16);
    record(&mut memory.memory, FRAME + 608, 0x45535201, 16);
    memory.memory.write(FRAME + 624, &fp).unwrap();
    record(&mut memory.memory, FRAME + 1152, 0, 0);
    memory.memory.unmap(FRAME + PAGE_SIZE, PAGE_SIZE).unwrap();
    let FrameProgress::Complete(done) = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        Some(SmeConfig::default()),
        false,
        None,
        &mut memory,
    ) else {
        panic!("no access to unused reserved bytes");
    };
    assert_eq!(done.state, saved);
}
#[test]
fn extra_context_accepts_extended_descriptor_and_native_256k_limit_without_reading_esr_payload() {
    let (signals, mut memory, state, saved) = fixture();
    let extra = FRAME + 1120;
    let data = extra + 48 + 16;
    record(&mut memory.memory, extra, EXTRA_MAGIC, 48);
    memory
        .memory
        .write_array(extra + 8, data.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(extra + 16, 16384u32.to_le_bytes())
        .unwrap();
    record(&mut memory.memory, extra + 48, 0, 0);
    record(&mut memory.memory, data, 0x45535201, 16368);
    record(&mut memory.memory, data + 16368, 0, 0);
    memory
        .memory
        .unmap(FRAME + PAGE_SIZE, 3 * PAGE_SIZE)
        .unwrap();
    let FrameProgress::Complete(done) = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        None,
        false,
        None,
        &mut memory,
    ) else {
        panic!("native extra_context bounds and ignored ESR body");
    };
    assert_eq!(done.state, saved);
}
#[test]
fn late_za_validation_failure_keeps_accepted_fp_and_tls_and_original_sme_state() {
    let (signals, mut memory, mut state, saved) = fixture();
    state.tpidr2_el0 = 0;
    record(&mut memory.memory, FRAME + 1120, TPIDR2_MAGIC, 16);
    memory
        .memory
        .write_array(FRAME + 1128, 0x456u64.to_le_bytes())
        .unwrap();
    record(&mut memory.memory, FRAME + 1136, ZA_MAGIC, 16);
    memory
        .memory
        .write_array(FRAME + 1144, 32u16.to_le_bytes())
        .unwrap();
    record(&mut memory.memory, FRAME + 1152, 0, 0);
    let original = SmeState {
        svcr: 2,
        za: [0x77; 4096],
        ..Default::default()
    };
    let FrameProgress::ReturnError { partial, .. } = signals.io.start_frame_return(
        signals.pending_frame_state(),
        state,
        Some(SmeConfig::default()),
        true,
        Some(&original),
        &mut memory,
    ) else {
        panic!("ZA VL mismatch");
    };
    assert_eq!(partial.state.vectors, saved.vectors);
    assert_eq!(partial.state.tpidr2_el0, 0x456);
    assert_eq!(partial.restored_sme.unwrap().unwrap().as_ref(), &original);
}
fn register_rseq(signals: &Signals, memory: &mut Reads) {
    memory
        .memory
        .write_array(0x1008, 0x1100u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1108, 0x4000u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1110, 0x40u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1118, 0x4080u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x407c, 0xd428bc00u32.to_le_bytes())
        .unwrap();
    signals
        .io
        .rseq
        .call(&mut memory.memory, [0x1000, 32, 0, 0xd428bc00, 0, 0])
        .unwrap();
    signals.io.rseq.preempt();
}
#[test]
fn rseq_abort_pc_and_completed_id_prefix_survive_later_tls_store_wait() {
    let (signals, mut memory, _, _) = fixture();
    register_rseq(&signals, &mut memory);
    memory.writing = Some(0x1004);
    let Some(FrameProgress::Rseq(crate::rseq::ResumeProgress::Page { pc, .. })) =
        signals.io.start_rseq_resume(0x4010, 3, &mut memory)
    else {
        panic!("CPU id output must wait after fixup");
    };
    assert_eq!(pc, 0x4080);
    assert_eq!(memory.memory.read_u64(0x1008).unwrap(), 0);
    memory
        .memory
        .write_array(0x1000, 77u32.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1008, 0x9000u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    let Some(FrameProgress::Rseq(crate::rseq::ResumeProgress::Complete(pc))) =
        signals.io.resume_frame(&mut memory)
    else {
        panic!("original notify-resume must finish");
    };
    assert_eq!(pc, 0x4080);
    assert_eq!(
        memory.memory.read_u64(0x1008).unwrap(),
        0x9000,
        "fixup is not performed twice"
    );
    assert_eq!(
        memory.memory.read_array::<4>(0x1000).unwrap(),
        77u32.to_le_bytes()
    );
    assert_eq!(
        memory.memory.read_array::<4>(0x1004).unwrap(),
        3u32.to_le_bytes()
    );
    assert!(signals.io.start_rseq_resume(pc, 3, &mut memory).is_none());
}
#[test]
fn rseq_unregister_keeps_registration_and_original_prefix_until_all_tls_stores_finish() {
    let (signals, mut memory, _, _) = fixture();
    register_rseq(&signals, &mut memory);
    memory.writing = Some(0x1004);
    let mut call = ControlCall::new(
        293,
        [0x1000, 32, 1, 0xd428bc00, 0, 0],
        0,
        signals.actions.shared(),
        signals.io_directory.clone(),
    );
    assert!(call.check(&signals.io, &mut memory).is_none());
    assert_eq!(
        signals
            .io
            .rseq
            .call(&mut memory.memory, [0x1000, 32, 0, 0xd428bc00, 0, 0]),
        Err(Errno(16))
    );
    memory
        .memory
        .write_array(0x1000, 77u32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&signals.io, &mut memory), Some(Ok(0)));
    assert_eq!(
        memory.memory.read_array::<4>(0x1000).unwrap(),
        77u32.to_le_bytes()
    );
    assert_eq!(
        memory.memory.read_array::<4>(0x1004).unwrap(),
        u32::MAX.to_le_bytes()
    );
    assert_eq!(
        signals
            .io
            .rseq
            .call(&mut memory.memory, [0x1000, 32, 0, 0xd428bc00, 0, 0]),
        Ok(0)
    );
    assert_eq!(
        call.check(&signals.io, &mut memory),
        Some(Ok(0)),
        "old completion cannot unregister the new registration"
    );
    assert_eq!(
        signals
            .io
            .rseq
            .call(&mut memory.memory, [0x1000, 32, 0, 0xd428bc00, 0, 0]),
        Err(Errno(16))
    );
}
#[test]
fn rseq_unregister_cancel_releases_copy_but_does_not_clear_the_original_registration() {
    let (signals, mut memory, _, _) = fixture();
    register_rseq(&signals, &mut memory);
    memory.writing = Some(0x1004);
    let mut call = ControlCall::new(
        293,
        [0x1000, 32, 1, 0xd428bc00, 0, 0],
        0,
        signals.actions.shared(),
        signals.io_directory.clone(),
    );
    assert!(call.check(&signals.io, &mut memory).is_none());
    call.cancel();
    memory.wait.finish();
    assert_eq!(call.check(&signals.io, &mut memory), Some(Err(Errno(4))));
    assert_eq!(
        signals
            .io
            .rseq
            .call(&mut memory.memory, [0x1000, 32, 0, 0xd428bc00, 0, 0]),
        Err(Errno(16))
    );
}
#[test]
fn valid_nested_frames_use_the_guest_stack_instead_of_an_internal_depth_limit() {
    let (mut signals, mut memory, mut state, _) = fixture();
    state.sp = 0x70000;
    let saved = state.clone();
    let frames = signals.frames;
    for _ in 0..12 {
        signals
            .enter(
                &mut state,
                &mut memory.memory,
                35,
                Info::default(),
                Action {
                    handler: 0x5000,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    for _ in 0..12 {
        signals.restore(&mut state, &memory.memory).unwrap();
    }
    assert_eq!(state, saved);
    assert_eq!(signals.frames, frames);
}
