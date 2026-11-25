// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Arc;
use trames_execution::Aarch64State;
use trames_memory::{Access, Memory, MemoryError, PageWait, Permissions, PAGE_SIZE};

pub(crate) struct Faults {
    pub(crate) memory: Memory,
    blocked: u64,
    pub(crate) wait: Arc<PageWait>,
}
impl Faults {
    pub(crate) fn new(blocked: u64) -> Self {
        let mut memory = Memory::default();
        memory.map(0x1000, 16 * PAGE_SIZE, Permissions::RW).unwrap();
        Self {
            memory,
            blocked,
            wait: Arc::default(),
        }
    }
    fn check_fault(&self, address: u64, size: usize) -> Result<(), MemoryError> {
        if address < self.blocked + PAGE_SIZE
            && address.saturating_add(size as u64) > self.blocked
            && !self.wait.ready()
        {
            Err(self.wait.fault(address.max(self.blocked)))
        } else {
            Ok(())
        }
    }
}
impl CpuMemory for Faults {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn async_faults_possible(&self) -> bool {
        true
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        self.check_fault(address, output.len())?;
        self.memory.read(address, output)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.check_fault(address, bytes.len())?;
        self.memory.write(address, bytes)
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.check_fault(address, len)?;
        self.memory.check(address, len, access)
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.memory.check_translation(address)
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.memory.fetch_u32(address)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(address)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("signal frame test")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("signal frame test")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("signal frame test")
    }
}

#[test]
fn accepted_frame_keeps_original_registers_mask_and_copied_prefix_until_the_last_page() {
    let mut signals = Signals {
        mask: 1 << 11,
        wait_mask: Some(1 << 2),
        ..Default::default()
    };
    let action = Action {
        handler: 0x5000,
        mask: 1 << 15,
        flags: 0x8000_0000,
        ..Default::default()
    };
    signals.actions.set(10, action);
    signals.begin_io();
    let mut state = Aarch64State {
        sp: 0x3000,
        pc: 0x4567,
        ..Default::default()
    };
    let original = state.clone();
    let mut memory = Faults::new(0x2000);
    assert!(signals
        .enter_sme_pending(&mut state, &mut memory, 10, Info::default(), action, None)
        .unwrap()
        .is_some());
    assert_eq!(state, original);
    assert_eq!(signals.frames, 0);
    assert_eq!(signals.mask, 1 << 11);
    assert_eq!(
        signals.actions.get(10),
        Action {
            handler: 0,
            ..action
        }
    );
    signals.actions.set(10, action);
    let frame = 0x3000 - 4688;
    assert_eq!(memory.memory.read_u64(frame + 168).unwrap(), 1 << 2);
    memory
        .memory
        .write_array(frame + 168, 0x1234u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert!(signals
        .resume_frame(&mut state, &mut memory)
        .unwrap()
        .is_none());
    assert!(!signals.io.has_pending_frame());
    assert_eq!(signals.frames, 1);
    assert_eq!(signals.wait_mask, None);
    assert_eq!(state.pc, action.handler);
    assert_eq!(
        memory.memory.read_u64(frame + 168).unwrap(),
        0x1234,
        "the completed prefix is not copied again"
    );
    assert_eq!(memory.memory.read_u64(frame + 568).unwrap(), original.pc);
    assert_eq!(
        signals.actions.get(10),
        action,
        "finishing the old frame must not reset a later identical installation"
    );
    assert_eq!(signals.io.context.lock().unwrap().frames, 1);
}

#[test]
fn accepted_rseq_fixup_keeps_read_fragments_and_original_signal_state_across_a_page_wait() {
    let mut signals = Signals::default();
    signals.begin_io();
    let mut memory = Faults::new(0x2000);
    let descriptor: u64 = 0x1ff0;
    let signature = 0xd428bc00u32;
    memory
        .memory
        .write_array(0x1008, descriptor.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(descriptor + 8, 0x4000u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(descriptor + 16, 0x40u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(descriptor + 24, 0x4080u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x407c, signature.to_le_bytes())
        .unwrap();
    signals
        .io
        .rseq
        .call(&mut memory.memory, [0x1000, 32, 0, signature as u64, 0, 0])
        .unwrap();
    let mut state = Aarch64State {
        sp: 0x10000,
        pc: 0x4010,
        ..Default::default()
    };
    let action = Action {
        handler: 0x5000,
        ..Default::default()
    };
    assert!(signals
        .enter_sme_pending(&mut state, &mut memory, 10, Info::default(), action, None)
        .unwrap()
        .is_some());
    memory
        .memory
        .write_array(0x1008, 0x9000u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(descriptor + 8, u64::MAX.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert!(signals
        .resume_frame(&mut state, &mut memory)
        .unwrap()
        .is_none());
    assert_eq!(state.pc, action.handler);
    assert_eq!(memory.memory.read_u64(state.sp + 568).unwrap(), 0x4080);
    assert_eq!(memory.memory.read_u64(0x1008).unwrap(), 0);
}

#[test]
fn abandoning_a_frame_releases_its_original_continuation_without_committing_a_handler() {
    let mut signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    let mut state = Aarch64State {
        sp: 0x3000,
        pc: 0x4567,
        ..Default::default()
    };
    let original = state.clone();
    assert!(signals
        .enter_sme_pending(
            &mut state,
            &mut memory,
            10,
            Info::default(),
            Action {
                handler: 0x5000,
                ..Default::default()
            },
            None
        )
        .unwrap()
        .is_some());
    signals.exec();
    memory.wait.finish();
    assert!(!signals.io.has_pending_frame());
    assert!(signals.io.resume_frame(&mut memory).is_none());
    assert_eq!(signals.frames, 0);
    assert_eq!(state, original);
}

#[test]
fn sigreturn_publishes_the_original_scalar_prefix_before_waiting_for_later_frame_pages() {
    let mut signals = Signals {
        mask: 1 << 3,
        ..Default::default()
    };
    let mut memory = Faults::new(0x2000);
    let mut state = Aarch64State {
        sp: 0x3000,
        pc: 0x4000,
        ..Default::default()
    };
    state.registers[0] = 37;
    signals
        .enter(
            &mut state,
            &mut memory.memory,
            10,
            Info::default(),
            Action {
                handler: 0x5000,
                ..Default::default()
            },
        )
        .unwrap();
    signals.begin_io();
    let frame = state.sp;
    let task = signals.io.clone();
    let progress = task.start_frame_return(
        signals.pending_frame_state(),
        state.clone(),
        None,
        false,
        None,
        &mut memory,
    );
    let FrameProgress::ReturnPage { partial, .. } = progress else {
        panic!("later record page must wait");
    };
    assert_eq!(partial.state.pc, 0x4000);
    assert_eq!(partial.state.registers[0], 37);
    assert_eq!(task.mask(), 1 << 3);
    assert_eq!(signals.frames, 1);
    assert_eq!(state.pc, 0x5000);
    memory
        .memory
        .write_array(frame + 168, 0x80u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(frame + 312, 99u64.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(frame + 568, 0x6000u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    let FrameProgress::Complete(completed) = task.resume_frame(&mut memory).unwrap() else {
        panic!("original frame must resume");
    };
    assert!(completed.returned);
    assert_eq!(completed.frame.frames, 0);
    assert_eq!(completed.frame.mask, 1 << 3);
    assert_eq!(completed.state.registers[0], 37);
    assert_eq!(completed.state.pc, 0x4000);
    assert!(!task.has_pending_frame());
    assert!(task.resume_frame(&mut memory).is_none());
}

#[test]
fn sigreturn_permanent_tail_failure_preserves_restored_scalars_and_finishes_the_original_continuation(
) {
    let mut signals = Signals::default();
    let mut memory = Faults::new(0x2000);
    let mut state = Aarch64State {
        sp: 0x3000,
        pc: 0x4000,
        ..Default::default()
    };
    signals
        .enter(
            &mut state,
            &mut memory.memory,
            10,
            Info::default(),
            Action {
                handler: 0x5000,
                ..Default::default()
            },
        )
        .unwrap();
    signals.begin_io();
    let task = signals.io.clone();
    assert!(matches!(
        task.start_frame_return(
            signals.pending_frame_state(),
            state.clone(),
            None,
            false,
            None,
            &mut memory
        ),
        FrameProgress::ReturnPage { .. }
    ));
    memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    memory.wait.finish();
    let Some(FrameProgress::ReturnError {
        error: Errno(14),
        partial,
        fault,
    }) = task.resume_frame(&mut memory)
    else {
        panic!("tail must fail");
    };
    assert_eq!(partial.state.pc, 0x4000);
    assert_eq!(partial.state.sp, 0x3000);
    assert_eq!(fault.address, 0x3000);
    assert!(!task.has_pending_frame());
    assert_eq!(state.pc, 0x5000);
    assert_eq!(signals.frames, 1);
    assert_eq!(task.context.lock().unwrap().frames, 1);
}
