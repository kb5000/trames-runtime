// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional software CPU backend. Native code is compiled only with an explicit
//! feature on supported hosts; products using only the interpreter never link it.
use trames_engine::{Cpu as Backend, DecodeStats, SliceOutcome};
use trames_execution::{Aarch64State, Features, Registers};
use trames_memory::{parallel::View, CpuMemory, Memory};

#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
mod features;
#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
mod memory_ops;
#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
mod native;

/// Actual process-host capabilities; absent when native JIT is not compiled.
pub fn host_features() -> Option<Features> {
    #[cfg(all(
        feature = "native-aarch64",
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    ))]
    {
        Some(features::profile().raw)
    }
    #[cfg(not(all(
        feature = "native-aarch64",
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    )))]
    {
        None
    }
}

pub const NATIVE_COMPILED: bool = cfg!(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
));

#[derive(Clone, Debug, Default)]
pub struct Cpu {
    inner: trames_interpreter::Cpu,
    fault_retired: u64,
}
#[derive(Default)]
pub struct Engine {
    interpreter: trames_interpreter::Engine,
    #[cfg(all(
        feature = "native-aarch64",
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    ))]
    native: native::Cache,
    pub stats: Stats,
}
#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub native_blocks: u64,
    pub native_instructions: u64,
    pub fallback_instructions: u64,
    /// SVC exits compiled directly, without interpreter entry or a host SVC.
    pub direct_syscall_exits: u64,
}
/// Cold compiler totals, never updated by individual executed instructions.
#[derive(Clone, Copy, Default, Debug)]
pub struct CompilationStats {
    pub blocks: u64,
    pub host_words: u64,
    pub register_loads: u64,
    pub register_stores: u64,
    /// Native sites that can reuse a previously checked unchanged guest address.
    pub address_reuses: u64,
}
/// Execution/link counters; per-instruction guest memory accesses are unchanged.
#[derive(Clone, Copy, Default, Debug)]
pub struct LinkStats {
    pub entries: u64,
    pub linked_blocks: u64,
    pub syscall_resumes: u64,
    pub lookups: u64,
}
/// Diagnostics updated only by native memory fragments, never scalar/SVC exits.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryStats {
    pub instructions: u64,
    pub staged: u64,
    pub fused_entries: u64,
    pub fused_blocks: u64,
    /// Inline LDR/STR through an entry-scoped hardware-protected CPU alias.
    pub hardware: u64,
    /// Hardware accesses using the register-held affine region/address path.
    pub direct: u64,
}
impl Engine {
    pub fn memory_stats(&self) -> MemoryStats {
        #[cfg(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        ))]
        {
            self.native.memory_stats()
        }
        #[cfg(not(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        )))]
        {
            MemoryStats::default()
        }
    }
    pub fn link_stats(&self) -> LinkStats {
        #[cfg(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        ))]
        {
            self.native.links_stats
        }
        #[cfg(not(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        )))]
        {
            LinkStats::default()
        }
    }

    pub fn compilation_stats(&self) -> CompilationStats {
        #[cfg(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        ))]
        {
            self.native.compilation_stats()
        }
        #[cfg(not(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        )))]
        {
            CompilationStats::default()
        }
    }
}
impl Cpu {
    pub fn interpreter(&self) -> &trames_interpreter::Cpu {
        &self.inner
    }
    pub fn run_slice(
        &mut self,
        engine: &mut Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome {
        self.fault_retired = 0;
        // Same slice borrow as the interpreter; no new global/resource lock.
        self.run_borrowed(engine, &mut *memory.cpu_slice(), budget)
    }
    fn run_borrowed(
        &mut self,
        engine: &mut Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome {
        let mut retired = 0;
        while retired < budget {
            #[cfg(all(
                feature = "native-aarch64",
                target_arch = "aarch64",
                any(target_os = "linux", target_os = "android")
            ))]
            {
                if let Some(instructions) =
                    engine
                        .native
                        .syscall(&mut self.inner, memory, budget - retired)
                {
                    engine.stats.native_blocks += 1;
                    engine.stats.native_instructions += instructions - 1;
                    engine.stats.direct_syscall_exits += 1;
                    return SliceOutcome::Syscall {
                        instructions: retired + instructions,
                    };
                }
            }
            #[cfg(all(
                feature = "native-aarch64",
                target_arch = "aarch64",
                any(target_os = "linux", target_os = "android")
            ))]
            match engine
                .native
                .execute(&mut self.inner, memory, budget - retired)
            {
                Ok(Some(exit)) => {
                    retired += exit.instructions;
                    engine.stats.native_blocks += exit.blocks;
                    // SVC is a translated control exit, separate from native
                    // guest ALU/branch instructions and fallback execution.
                    engine.stats.native_instructions += exit.instructions - u64::from(exit.syscall);
                    if exit.syscall {
                        engine.stats.direct_syscall_exits += 1;
                        return SliceOutcome::Syscall {
                            instructions: retired,
                        };
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    let (instructions, blocks) = engine.native.take_fault_progress();
                    self.fault_retired = retired + instructions;
                    engine.stats.native_instructions += instructions;
                    engine.stats.native_blocks += blocks;
                    return SliceOutcome::Fault(error);
                }
            }
            // Unsupported instructions keep all interpreter state, including
            // deferred flags, TLS, FP/SIMD and exclusive reservations.
            let outcome = self
                .inner
                .run_with_engine(&mut engine.interpreter, memory, 1);
            match outcome {
                SliceOutcome::Yield { instructions } => {
                    retired += instructions;
                    engine.stats.fallback_instructions += instructions;
                    if instructions == 0 {
                        return SliceOutcome::Yield {
                            instructions: retired,
                        };
                    }
                }
                SliceOutcome::Syscall { instructions } => {
                    engine.stats.fallback_instructions += instructions;
                    return SliceOutcome::Syscall {
                        instructions: retired + instructions,
                    };
                }
                SliceOutcome::NativeCall {
                    instructions,
                    pc,
                    module,
                    function,
                } => {
                    return SliceOutcome::NativeCall {
                        instructions: retired + instructions,
                        pc,
                        module,
                        function,
                    };
                }
                SliceOutcome::Fault(error) => {
                    self.fault_retired = retired + self.inner.fault_retired();
                    return SliceOutcome::Fault(error);
                }
            }
        }
        SliceOutcome::Yield {
            instructions: retired,
        }
    }
}
impl Registers for Cpu {
    fn x(&self, index: usize) -> u64 {
        self.inner.x(index)
    }
    fn set_x(&mut self, index: usize, value: u64) {
        self.inner.set_x(index, value);
    }
    fn pc(&self) -> u64 {
        self.inner.pc
    }
}
impl Backend for Cpu {
    type Engine = Engine;
    const FEATURES: Features = Features {
        hwcap: 3,
        hwcap2: 0,
    };
    const FEATURE_NAMES: &'static str = "fp asimd";
    fn features() -> Features {
        #[cfg(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        ))]
        {
            features::profile().allowed
        }
        #[cfg(not(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        )))]
        {
            <trames_interpreter::Cpu as Backend>::features()
        }
    }
    fn feature_names() -> &'static str {
        #[cfg(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        ))]
        {
            &features::profile().names
        }
        #[cfg(not(all(
            feature = "native-aarch64",
            target_arch = "aarch64",
            any(target_os = "linux", target_os = "android")
        )))]
        {
            <trames_interpreter::Cpu as Backend>::feature_names()
        }
    }
    const EXACT_INSTRUCTIONS: bool = true;
    fn new(pc: u64, sp: u64) -> Self {
        Self {
            inner: trames_interpreter::Cpu::new(pc, sp),
            fault_retired: 0,
        }
    }
    fn counter_frequency() -> u64 {
        <trames_interpreter::Cpu as Backend>::counter_frequency()
    }
    fn sp(&self) -> u64 {
        self.inner.sp
    }
    fn set_sp(&mut self, value: u64) {
        self.inner.sp = value;
    }
    fn set_pc(&mut self, value: u64) {
        self.inner.pc = value;
    }
    fn set_tls(&mut self, value: u64) {
        self.inner.tpidr_el0 = value;
    }
    fn architectural_state(&self) -> Aarch64State {
        self.inner.architectural_state()
    }
    fn restore_architectural_state(&mut self, state: &Aarch64State) {
        self.inner.restore_architectural_state(state);
    }
    fn set_native_calls(&mut self, enabled: bool) {
        self.inner.set_native_calls(enabled);
    }
    fn set_vulkan_calls(&mut self, enabled: bool) {
        self.inner.set_vulkan_calls(enabled);
    }
    fn set_audio_calls(&mut self, enabled: bool) {
        self.inner.set_audio_calls(enabled);
    }
    fn set_video_calls(&mut self, enabled: bool) {
        self.inner.set_video_calls(enabled);
    }
    fn clear_exclusive(&mut self) {
        self.inner.clear_exclusive();
    }
    fn fault_retired(&self) -> u64 {
        self.fault_retired
    }
    fn decode_stats(&self) -> DecodeStats {
        self.inner.decode_stats()
    }
    fn run(&mut self, engine: &mut Engine, memory: &mut Memory, budget: u64) -> SliceOutcome {
        self.run_slice(engine, memory, budget)
    }
    fn run_parallel(
        &mut self,
        engine: &mut Engine,
        memory: &mut View,
        budget: u64,
    ) -> SliceOutcome {
        self.run_slice(engine, memory, budget)
    }
}
