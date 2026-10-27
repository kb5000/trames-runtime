// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold task/executor interface. Ordinary guest instructions and accesses stay
//! inside each engine, with static dispatch and its existing memory model.
use std::fmt;
use trames_execution::{Aarch64State, Features, Registers};
use trames_memory::{parallel::View, Memory, MemoryError};

#[derive(Default, Clone, Copy, Debug)]
pub struct DecodeStats {
    pub lookups: u64,
    pub misses: u64,
    pub instructions: u64,
}

#[derive(Debug)]
pub enum CpuFault {
    /// Host transport failure; never converted to a guest signal.
    Host(String),
    Memory {
        pc: u64,
        error: MemoryError,
    },
    Instruction {
        pc: u64,
        instruction: u32,
    },
    Trap {
        pc: u64,
        instruction: u32,
        signal: u32,
        code: i32,
    },
}
impl fmt::Display for CpuFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(error) => write!(f, "execution backend: {error}"),
            Self::Memory { pc, error } => write!(f, "CPU fault at PC {pc:#x}: {error}"),
            Self::Trap {
                pc,
                instruction,
                signal,
                ..
            } => write!(
                f,
                "CPU exception {instruction:#010x} at PC {pc:#x} (signal {signal})"
            ),
            Self::Instruction { pc, instruction } => write!(
                f,
                "unsupported or unallocated instruction {instruction:#010x} at PC {pc:#x}"
            ),
        }
    }
}
impl std::error::Error for CpuFault {}

#[derive(Debug)]
pub enum SliceOutcome {
    Syscall {
        instructions: u64,
    },
    /// Instructions before the pending HLT; it retires only on a committed return.
    NativeCall {
        instructions: u64,
        pc: u64,
        module: u64,
        function: u64,
    },
    Yield {
        instructions: u64,
    },
    Fault(CpuFault),
}

/// Movable task state is separate from the host-thread-affine execution engine.
/// Engines are created on the thread that executes them and never sent to a
/// worker. Interpreter states retain their decoder and deferred flags in place.
pub trait Cpu: Registers + Default + Clone + Send + 'static {
    type Engine: Default;
    const FEATURES: Features;
    const FEATURE_NAMES: &'static str;
    const PARALLEL: bool;
    const EXACT_INSTRUCTIONS: bool;
    fn new(pc: u64, sp: u64) -> Self;
    fn sp(&self) -> u64;
    fn set_sp(&mut self, value: u64);
    fn set_pc(&mut self, value: u64);
    fn set_tls(&mut self, value: u64);
    fn architectural_state(&self) -> Aarch64State;
    fn restore_architectural_state(&mut self, state: &Aarch64State);
    fn set_native_calls(&mut self, enabled: bool);
    fn set_vulkan_calls(&mut self, enabled: bool);
    fn clear_exclusive(&mut self);
    fn fault_retired(&self) -> u64;
    fn decode_stats(&self) -> DecodeStats;
    fn run(&mut self, engine: &mut Self::Engine, memory: &mut Memory, budget: u64) -> SliceOutcome;
    /// Session-owned registration domain, shared by serial and worker dispatch.
    /// Interpreters keep their direct Memory path; hardware backends must avoid
    /// replacing a VM's snapshot domain when its runnable CPU count changes.
    fn run_coordinated(
        &mut self,
        engine: &mut Self::Engine,
        memory: &mut Memory,
        registry: &mut trames_memory::parallel::Registry,
        budget: u64,
    ) -> SliceOutcome {
        let _ = registry;
        self.run(engine, memory, budget)
    }
    fn prepare_hardware_memory(
        _: &mut Memory,
        _: &mut trames_memory::parallel::Registry,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
    fn prepare_hardware_view(view: &mut View) {
        let _ = view;
    }
    fn take_hardware_wait(
        _: &mut Self::Engine,
    ) -> Option<std::sync::Arc<trames_memory::HardwareWait>> {
        None
    }
    fn run_parallel(
        &mut self,
        engine: &mut Self::Engine,
        memory: &mut View,
        budget: u64,
    ) -> SliceOutcome;
}
