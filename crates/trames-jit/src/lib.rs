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
mod native;

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
            match engine
                .native
                .execute(&mut self.inner, memory, budget - retired)
            {
                Ok(Some(count)) => {
                    retired += count;
                    engine.stats.native_blocks += 1;
                    engine.stats.native_instructions += count;
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    self.fault_retired = retired;
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
    const FEATURES: Features = <trames_interpreter::Cpu as Backend>::FEATURES;
    const FEATURE_NAMES: &'static str = <trames_interpreter::Cpu as Backend>::FEATURE_NAMES;
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
