// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold task/executor interface. Ordinary guest instructions and accesses stay
//! inside each engine, with static dispatch and its existing memory model.
use std::fmt;
use trames_execution::{Aarch64State, Features, Registers, SmeConfig, SmeState};
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
impl CpuFault {
    pub fn pending_page(&self) -> Option<&trames_memory::PageFault> {
        match self {
            Self::Memory {
                error: MemoryError::Pending(fault),
                ..
            } => Some(fault),
            _ => None,
        }
    }
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

/// A backend counter with the same domain as the guest's CNTVCT_EL0.
/// The hardware backend must preserve this domain across vCPU migration/sleep.
#[derive(Clone, Copy)]
pub struct ClockSample {
    pub ticks: u64,
    pub frequency: u64,
}

pub use trames_execution::ExecutionInterrupt;

/// Movable task state is separate from the host-thread-affine execution engine.
/// Engines are created on the thread that executes them and never sent to a
/// worker. Interpreter states retain their decoder and deferred flags in place.
pub trait Cpu: Registers + Default + Clone + Send + 'static {
    type Engine: Default;
    /// Whether execution can alias retained native allocations without a file
    /// descriptor. Backends needing a second revocable file alias opt out at
    /// compile time; this never adds an ordinary memory-access check.
    const NATIVE_POINTER_IMPORTS: bool = true;
    /// Optional coherent counter for the common Linux monotonic clock vDSO.
    /// Without a counter the vDSO delegates clock reads to Linux syscalls.
    fn clock_sample() -> Option<ClockSample> {
        None
    }

    /// Frequency of the guest architectural delay timer, for ARM64 cpuinfo.
    fn counter_frequency() -> u64 {
        Self::clock_sample().map_or(0, |sample| sample.frequency)
    }

    /// Prepare the thread-affine engine on its worker before the first CPU
    /// entry of an assignment. Software engines use their existing local poll.
    fn execution_interrupt(
        _: &mut Self::Engine,
    ) -> Result<Option<std::sync::Arc<dyn ExecutionInterrupt>>, CpuFault> {
        Ok(None)
    }
    /// Begin one worker assignment before binding its interrupt. A backend may
    /// retain a bounded execution budget across short syscall returns. Direct
    /// and quiesced CPU calls retain their existing per-call lifetime.
    fn begin_execution(
        engine: &mut Self::Engine,
    ) -> Result<Option<std::sync::Arc<dyn ExecutionInterrupt>>, CpuFault> {
        Self::execution_interrupt(engine)
    }
    /// Release assignment-local host resources on the original worker before
    /// parking, switching tasks, returning a fault, or completing a caught panic.
    /// Called even when entry/binding failed; default backends compile to a no-op.
    fn finish_execution(_: &mut Self::Engine) {}
    const FEATURES: Features;
    const FEATURE_NAMES: &'static str;
    /// A backend may query its actual execution configuration once at runtime.
    /// Static interpreter profiles keep the existing constants by default.
    fn features() -> Features {
        Self::FEATURES
    }
    fn feature_names() -> &'static str {
        Self::FEATURE_NAMES
    }
    const EXACT_INSTRUCTIONS: bool;
    fn new(pc: u64, sp: u64) -> Self;
    fn sp(&self) -> u64;
    fn set_sp(&mut self, value: u64);
    fn set_pc(&mut self, value: u64);
    fn set_tls(&mut self, value: u64);
    fn architectural_state(&self) -> Aarch64State;
    fn restore_architectural_state(&mut self, state: &Aarch64State);
    /// Optional Linux SME ABI; interpreters incur no extra register storage.
    fn sme_config(&self) -> Option<SmeConfig> {
        None
    }
    fn sme_lengths() -> &'static [u16] {
        &[]
    }
    fn set_sme_config(&mut self, _: SmeConfig) {}
    fn sme_state(&self) -> Option<&SmeState> {
        None
    }
    fn set_sme_state(&mut self, _: Option<Box<SmeState>>) {}
    fn fork_cpu(&self, _: bool) -> Self {
        self.clone()
    }
    fn inherit_exec(&mut self, _: &Self) {}
    fn set_native_calls(&mut self, enabled: bool);
    fn set_vulkan_calls(&mut self, enabled: bool);
    fn set_video_calls(&mut self, _enabled: bool) {}
    fn set_audio_calls(&mut self, _enabled: bool) {}
    /// Exact engines use a one-instruction budget; hardware engines arm their
    /// architectural single-step exception through this task-local hook.
    fn set_single_step(&mut self, _enabled: bool) {}
    fn clear_exclusive(&mut self);
    fn fault_retired(&self) -> u64;
    fn decode_stats(&self) -> DecodeStats;
    fn run(&mut self, engine: &mut Self::Engine, memory: &mut Memory, budget: u64) -> SliceOutcome;
    /// Optional bounded CPU run while the caller already exclusively owns
    /// this mm at a mapping checkpoint. No native operation is executed here;
    /// an exit is returned to the ordinary worker dispatch. Software engines
    /// keep their existing coordinator policy and return None. Only engines
    /// with unavailable instruction counts may opt in; exact engines need
    /// the ordinary budget-owning worker path.
    fn run_quiesced(
        &mut self,
        _: &mut Self::Engine,
        _: &mut Memory,
        _: &mut trames_memory::parallel::Registry,
        _: std::time::Duration,
    ) -> Option<SliceOutcome> {
        None
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
