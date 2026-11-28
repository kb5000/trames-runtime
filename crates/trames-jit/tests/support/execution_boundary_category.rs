// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use trames_memory::{Access, InstructionEpochs, MemoryError};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hook {
    Identity,
    Page,
}
/// Deterministic publication during the original compile/entry window. Only a
/// global epoch changes; this page's bytes/identity remain valid and reusable.
/// No production hook, thread, additional epoch load or code patch is needed.
struct Changing {
    memory: Memory,
    counters: [AtomicU64; 3],
    index: usize,
    hook: Hook,
    page_target: Option<u64>,
    remaining: Cell<u64>,
    fetches: Cell<u64>,
    reads: Cell<u64>,
    #[cfg(feature = "native-aarch64")]
    hardware: bool,
}
impl Changing {
    fn new(memory: Memory, index: usize, hook: Hook, hardware: bool) -> Self {
        #[cfg(not(feature = "native-aarch64"))]
        let _ = hardware;
        Self {
            memory,
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            index,
            hook,
            page_target: None,
            remaining: Cell::new(0),
            fetches: Cell::new(0),
            reads: Cell::new(0),
            #[cfg(feature = "native-aarch64")]
            hardware,
        }
    }
    fn publish(&self, hook: Hook) {
        if self.hook == hook && self.remaining.get() != 0 {
            self.remaining.set(self.remaining.get() - 1);
            self.counters[self.index].fetch_add(
                1,
                if self.index == 0 {
                    Ordering::Release
                } else {
                    Ordering::Relaxed
                },
            );
        }
    }
}
impl CpuMemory for Changing {
    fn mapped_at_or_after(&self, a: u64) -> bool {
        self.memory.mapped_at_or_after(a)
    }
    fn read(&self, a: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        self.reads.set(self.reads.get() + 1);
        self.memory.read(a, out)
    }
    fn write(&mut self, a: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write(a, bytes)
    }
    fn check(&self, a: u64, n: usize, access: Access) -> Result<(), MemoryError> {
        self.memory.check(a, n, access)
    }
    fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
        self.memory.check_translation(a)
    }
    fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
        self.fetches.set(self.fetches.get() + 1);
        self.memory.fetch_u32(a)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        let (a, b, c) = self.memory.instruction_identity();
        let sampled = self.counters[self.index].load(if self.index == 0 {
            Ordering::Acquire
        } else {
            Ordering::Relaxed
        });
        self.publish(Hook::Identity);
        (a, b, c.wrapping_add(sampled))
    }
    fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
        let page = self.memory.instruction_page_identity(a)?;
        if self.page_target.is_none_or(|target| target == a) {
            self.publish(Hook::Page);
        }
        Ok(page)
    }
    fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
        Some(InstructionEpochs(std::array::from_fn(|i| {
            (i == self.index).then_some(&self.counters[i])
        })))
    }
    fn atomic_update<T>(
        &mut self,
        a: u64,
        n: usize,
        f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        CpuMemory::atomic_update(&mut self.memory, a, n, f)
    }
    fn exclusive_read(&mut self, a: u64, out: &mut [u8]) -> Result<u128, MemoryError> {
        CpuMemory::exclusive_read(&mut self.memory, a, out)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        bytes: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        CpuMemory::exclusive_write(&mut self.memory, a, bytes, token)
    }
    #[cfg(feature = "native-aarch64")]
    fn cpu_hardware_ordering(&self) -> bool {
        true
    }
    #[cfg(feature = "native-aarch64")]
    fn cpu_native_available(&self) -> bool {
        self.hardware && self.memory.cpu_native_available()
    }
    #[cfg(feature = "native-aarch64")]
    unsafe fn cpu_native_page(&mut self, a: u64, write: bool) -> Option<trames_memory::NativePage> {
        unsafe { self.memory.cpu_native_page(a, write) }
    }
}
fn populated(words: &[u32]) -> Memory {
    let mut m = memory(words);
    m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
    m.write(0x10000, &vec![0x5c; hardware_span() as usize])
        .unwrap();
    m
}
fn state() -> Aarch64State {
    let mut state = initial();
    state.nzcv = 0xb0000000; // public architectural ABI stores bits 31..28
    state.registers[1] = 0x10000;
    state.vectors[1] = 1.5f64.to_bits() as u128;
    state.vectors[2] = 2.25f64.to_bits() as u128;
    state
}
fn programs() -> [&'static [u32]; 3] {
    [
        &[0x1e622820, 0xd4000001], // pure FP/vector scope
        &[0xf9400020, 0xf9000020, 0xf9400020, 0xf9000020, 0xd4000001],
        &[0x1e622820, 0x3d800020, 0x3dc0003f, 0xd4000001], // mixed FP + memory
    ]
}
fn assert_text(m: &Memory, words: &[u32]) {
    for (i, word) in words.iter().enumerate() {
        assert_eq!(m.fetch_u32(0x1000 + i as u64 * 4).unwrap(), *word);
    }
}
#[cfg(target_arch = "aarch64")]
fn host_fp_state() -> (u64, u64) {
    let (control, status);
    unsafe {
        std::arch::asm!("mrs {},fpcr", "mrs {},fpsr", out(reg) control, out(reg) status, options(nomem, nostack, preserves_flags));
    }
    (control, status)
}
#[cfg(not(target_arch = "aarch64"))]
fn host_fp_state() -> (u64, u64) {
    (0, 0)
}

#[test]
fn stale_vector_checked_hardware_and_mixed_entries_retry_all_epoch_channels_without_interpreter() {
    if !NATIVE_COMPILED {
        return;
    }
    for index in 0..3 {
        for hook in [Hook::Identity, Hook::Page] {
            for hardware in [false, true] {
                for words in programs() {
                    for budget in [1, 2, 64] {
                        let mut m = Changing::new(populated(words), index, hook, hardware);
                        m.remaining.set(1);
                        let mut expected_memory = populated(words);
                        let mut reference = trames_interpreter::Cpu::new(0, 0);
                        let mut cpu = Cpu::new(0, 0);
                        reference.restore_architectural_state(&state());
                        cpu.restore_architectural_state(&state());
                        let mut engine = Engine::default();
                        for _ in 0..16 {
                            let host = host_fp_state();
                            let actual = cpu.run_slice(&mut engine, &mut m, budget);
                            assert_eq!(host_fp_state(), host);
                            let expected = reference.run_slice(&mut expected_memory, budget);
                            assert_eq!(
                                format!("{actual:?}"),
                                format!("{expected:?}"),
                                "{words:x?}; {index}; {hook:?}; {hardware}; {budget}"
                            );
                            assert_eq!(cpu.architectural_state(), reference.architectural_state());
                            assert_eq!(cpu.fault_retired(), reference.fault_retired());
                            assert_eq!(
                                m.memory.read_array::<64>(0x10000).unwrap(),
                                expected_memory.read_array::<64>(0x10000).unwrap()
                            );
                            assert_text(&m.memory, words);
                            if !matches!(actual, SliceOutcome::Yield { .. }) {
                                break;
                            }
                        }
                        assert_eq!(m.remaining.get(), 0);
                        assert_eq!(engine.stats.fallback_instructions, 0);
                        assert!(engine.link_stats().entries >= 2);
                        assert_eq!(cpu.pc(), 0x1000 + words.len() as u64 * 4);
                    }
                }
            }
        }
    }
}

#[test]
fn stale_linked_scalar_entries_reuse_unchanged_pages_without_interpreter_fetch_or_retirement() {
    if !NATIVE_COMPILED {
        return;
    }
    let words = [0x91000400, 0x17ffffff];
    for index in 0..3 {
        for hardware in [false, true] {
            let mut m = Changing::new(populated(&words), index, Hook::Identity, hardware);
            let mut cpu = Cpu::new(0x1000, 0);
            let mut engine = Engine::default();
            assert!(matches!(
                cpu.run_slice(&mut engine, &mut m, 4),
                SliceOutcome::Yield { instructions: 4 }
            ));
            let before = engine.stats;
            let fetches = m.fetches.get();
            let blocks = engine.compilation_stats().blocks;
            let entries = engine.link_stats().entries;
            m.remaining.set(1);
            assert!(matches!(
                cpu.run_slice(&mut engine, &mut m, 4),
                SliceOutcome::Yield { instructions: 4 }
            ));
            assert_eq!((cpu.x(0), cpu.pc()), (4, 0x1000));
            assert_eq!(
                engine.stats.native_instructions - before.native_instructions,
                4
            );
            assert_eq!(engine.stats.fallback_instructions, 0);
            assert_eq!(
                m.fetches.get(),
                fetches,
                "revalidation needs no decoder for an unchanged page"
            );
            assert_eq!(engine.compilation_stats().blocks, blocks);
            assert!(engine.link_stats().entries - entries >= 3);
            assert_text(&m.memory, &words);
        }
    }
}

#[test]
fn repeated_invalidation_yields_after_two_empty_entries_then_resumes_exactly() {
    if !NATIVE_COMPILED {
        return;
    }
    for index in 0..3 {
        for hardware in [false, true] {
            for words in programs() {
                for budget in [1, 2, 64] {
                    let mut m = Changing::new(populated(words), index, Hook::Identity, hardware);
                    m.remaining.set(100);
                    let mut cpu = Cpu::new(0, 0);
                    cpu.restore_architectural_state(&state());
                    let mut engine = Engine::default();
                    let host = host_fp_state();
                    assert!(matches!(
                        cpu.run_slice(&mut engine, &mut m, budget),
                        SliceOutcome::Yield { instructions: 0 }
                    ));
                    assert_eq!(host_fp_state(), host);
                    assert_eq!(
                        cpu.architectural_state(),
                        state(),
                        "{index}; {hardware}; {words:x?}; {budget}"
                    );
                    assert_eq!(
                        (
                            engine.stats.native_blocks,
                            engine.stats.native_instructions,
                            engine.stats.fallback_instructions
                        ),
                        (0, 0, 0)
                    );
                    assert_eq!(
                        (
                            m.remaining.get(),
                            engine.link_stats().entries,
                            m.reads.get()
                        ),
                        (98, 2, 0)
                    );
                    assert_eq!(m.memory.read_array::<64>(0x10000).unwrap(), [0x5c; 64]);
                    m.remaining.set(0);
                    let mut reference_memory = populated(words);
                    let mut reference = trames_interpreter::Cpu::new(0, 0);
                    reference.restore_architectural_state(&state());
                    for _ in 0..16 {
                        let actual = cpu.run_slice(&mut engine, &mut m, budget);
                        let expected = reference.run_slice(&mut reference_memory, budget);
                        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                        assert_eq!(cpu.architectural_state(), reference.architectural_state());
                        assert_eq!(cpu.fault_retired(), reference.fault_retired());
                        if !matches!(actual, SliceOutcome::Yield { .. }) {
                            break;
                        }
                    }
                    assert_eq!(cpu.pc(), 0x1000 + words.len() as u64 * 4);
                    assert_eq!(engine.stats.fallback_instructions, 0);
                    assert_eq!(
                        m.memory.read_array::<64>(0x10000).unwrap(),
                        reference_memory.read_array::<64>(0x10000).unwrap()
                    );
                    assert_text(&m.memory, words);
                }
            }
        }
    }
}

fn prefix_program(tail: u32) -> Vec<u32> {
    vec![
        0xb1000529, 0x14000003, 0xd503201f, 0xd503201f, 0x1e622820, tail,
    ]
}
fn prefix_state() -> Aarch64State {
    let mut s = state();
    s.registers[9] = u64::MAX; // committed ADDS produces nonzero Z/C flags
    s.registers[3] = 0x3000; // missing data page for the faulting-tail case
    s.registers[16] = 0x10006;
    s.registers[17] = 7;
    s
}

#[test]
fn retry_after_a_dirty_prefix_preserves_yield_syscall_native_call_and_fault_totals() {
    if !NATIVE_COMPILED {
        return;
    }
    for index in 0..3 {
        for hardware in [false, true] {
            for tail in [0xd4000001, 0xd44a8a40, 0xd4200000, 0xf9400060] {
                for budget in [3, 64] {
                    let words = prefix_program(tail);
                    let mut m = Changing::new(populated(&words), index, Hook::Page, hardware);
                    m.page_target = Some(0x1010);
                    m.remaining.set(1);
                    let mut expected_memory = populated(&words);
                    let mut reference = trames_interpreter::Cpu::new(0, 0);
                    let mut cpu = Cpu::new(0, 0);
                    reference.restore_architectural_state(&prefix_state());
                    cpu.restore_architectural_state(&prefix_state());
                    reference.set_native_calls(true);
                    cpu.set_native_calls(true);
                    let mut engine = Engine::default();
                    for _ in 0..8 {
                        let host = host_fp_state();
                        let actual = cpu.run_slice(&mut engine, &mut m, budget);
                        assert_eq!(host_fp_state(), host);
                        let expected = reference.run_slice(&mut expected_memory, budget);
                        assert_eq!(
                            format!("{actual:?}"),
                            format!("{expected:?}"),
                            "{index}; {hardware}; {tail:x}; {budget}"
                        );
                        assert_eq!(cpu.architectural_state(), reference.architectural_state());
                        assert_eq!(cpu.fault_retired(), reference.fault_retired());
                        assert_eq!(cpu.architectural_state().nzcv, 0x60000000);
                        if !matches!(actual, SliceOutcome::Yield { .. }) {
                            break;
                        }
                    }
                    assert_eq!(m.remaining.get(), 0);
                    assert_eq!(engine.stats.fallback_instructions, 0);
                    assert_text(&m.memory, &words);
                }
            }
        }
    }
}

#[test]
fn repeated_target_invalidation_yields_only_the_committed_prefix_then_resumes() {
    if !NATIVE_COMPILED {
        return;
    }
    for index in 0..3 {
        for hardware in [false, true] {
            let words = prefix_program(0xd4000001);
            let mut m = Changing::new(populated(&words), index, Hook::Page, hardware);
            m.page_target = Some(0x1010);
            m.remaining.set(2);
            let mut cpu = Cpu::new(0, 0);
            cpu.restore_architectural_state(&prefix_state());
            let mut reference_memory = populated(&words);
            let mut reference = trames_interpreter::Cpu::new(0, 0);
            reference.restore_architectural_state(&prefix_state());
            let mut engine = Engine::default();
            assert!(matches!(
                cpu.run_slice(&mut engine, &mut m, 64),
                SliceOutcome::Yield { instructions: 2 }
            ));
            assert!(matches!(
                reference.run_slice(&mut reference_memory, 2),
                SliceOutcome::Yield { instructions: 2 }
            ));
            assert_eq!(cpu.architectural_state(), reference.architectural_state());
            assert_eq!(m.remaining.get(), 0);
            assert_eq!(engine.link_stats().entries, 3); // source + two rejected entries
            assert_eq!(
                (
                    engine.stats.native_instructions,
                    engine.stats.native_blocks,
                    engine.stats.fallback_instructions
                ),
                (2, 1, 0)
            );
            assert_eq!(cpu.pc(), 0x1010);
            let actual = cpu.run_slice(&mut engine, &mut m, 64);
            let expected = reference.run_slice(&mut reference_memory, 64);
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
            assert_eq!(cpu.architectural_state(), reference.architectural_state());
            assert_eq!(cpu.fault_retired(), 0);
            assert_eq!(engine.stats.fallback_instructions, 0);
            assert_text(&m.memory, &words);
        }
    }
}

#[test]
fn empty_native_entries_preserve_every_architectural_nzcv_combination() {
    if !NATIVE_COMPILED {
        return;
    }
    for flags in 0..16 {
        for index in 0..3 {
            for hardware in [false, true] {
                for words in programs() {
                    let mut m = Changing::new(populated(words), index, Hook::Identity, hardware);
                    m.remaining.set(2);
                    let mut state = state();
                    state.nzcv = flags << 28;
                    let mut cpu = Cpu::new(0, 0);
                    cpu.restore_architectural_state(&state);
                    let mut engine = Engine::default();
                    assert!(matches!(
                        cpu.run_slice(&mut engine, &mut m, 64),
                        SliceOutcome::Yield { instructions: 0 }
                    ));
                    assert_eq!(cpu.architectural_state(), state);
                    assert_eq!(engine.stats.fallback_instructions, 0);
                    assert_eq!(engine.link_stats().entries, 2);
                    assert_eq!(m.remaining.get(), 0);
                }
            }
        }
    }
}

#[test]
fn a_cooperative_invalidation_exit_preserves_the_original_exclusive_reservation() {
    if !NATIVE_COMPILED {
        return;
    }
    let words = [
        0xc85f7c20, 0x14000003, 0xd503201f, 0xd503201f, 0x1e622820, 0xc8037c32, 0xd4000001,
    ];
    let cookie = 0x1234_5678_9abc_def0;
    for index in 0..3 {
        for hardware in [false, true] {
            let mut successes = 0;
            for _ in 0..8 {
                let mut m = Changing::new(populated(&words), index, Hook::Page, hardware);
                m.page_target = Some(0x1010);
                m.remaining.set(2);
                let mut state = state();
                state.registers[18] = cookie;
                let mut cpu = Cpu::new(0, 0);
                cpu.restore_architectural_state(&state);
                let mut engine = Engine::default();
                assert!(matches!(
                    cpu.run_slice(&mut engine, &mut m, 64),
                    SliceOutcome::Yield { instructions: 2 }
                ));
                assert_eq!(cpu.pc(), 0x1010);
                assert_eq!(m.memory.read_u64(0x10000).unwrap(), 0x5c5c_5c5c_5c5c_5c5c);
                assert!(matches!(
                    cpu.run_slice(&mut engine, &mut m, 64),
                    SliceOutcome::Syscall { instructions: 3 }
                ));
                let status = cpu.x(3);
                assert!(status <= 1);
                if status == 0 {
                    successes += 1;
                }
                assert_eq!(
                    m.memory.read_u64(0x10000).unwrap(),
                    if status == 0 {
                        cookie
                    } else {
                        0x5c5c_5c5c_5c5c_5c5c
                    }
                );
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
            // Real STXR is allowed to fail spuriously. Losing the guest token
            // on every empty entry is not a permitted implementation strategy.
            assert!(successes > 0, "{index}; {hardware}");
        }
    }
}

#[test]
fn guest_self_modification_revalidates_memory_helper_exits_in_all_execution_modes() {
    for replacement in [0x91000800, 0xd4000001, 0xd4200000, 0xd44a8a40, 0xf9400060] {
        // This is an explicit guest-authorized W+X store, not a backend patch.
        let words = [0x1e622820, 0xb1000529, 0xb9000032, 0x91010000, 0xd4000001];
        for mode in 0..3 {
            for budget in [1, 2, 3, 64] {
                let mut a = populated(&words);
                let mut b = populated(&words);
                let rwx = Permissions {
                    read: true,
                    write: true,
                    execute: true,
                };
                a.protect(0x1000, PAGE_SIZE, rwx).unwrap();
                b.protect(0x1000, PAGE_SIZE, rwx).unwrap();
                let mut ra = trames_memory::parallel::Registry::default();
                let mut rb = trames_memory::parallel::Registry::default();
                let mut va = (mode != 0).then(|| a.parallel_view(&mut ra).unwrap());
                let mut vb = (mode != 0).then(|| b.parallel_view(&mut rb).unwrap());
                if mode == 2 {
                    assert!(unsafe {
                        trames_memory::parallel::View::try_private_epoch(&mut [va
                            .as_mut()
                            .unwrap()])
                    });
                    assert!(unsafe {
                        trames_memory::parallel::View::try_private_epoch(&mut [vb
                            .as_mut()
                            .unwrap()])
                    });
                }
                let mut state = prefix_state();
                state.registers[0] = 40;
                state.registers[1] = 0x100c;
                state.registers[18] = replacement as u64;
                let mut cpu = Cpu::new(0, 0);
                let mut reference = trames_interpreter::Cpu::new(0, 0);
                cpu.restore_architectural_state(&state);
                reference.restore_architectural_state(&state);
                cpu.set_native_calls(true);
                reference.set_native_calls(true);
                let mut engine = Engine::default();
                let mut re = trames_interpreter::Engine::default();
                for _ in 0..16 {
                    let actual = if let Some(view) = &mut vb {
                        cpu.run_parallel(&mut engine, view, budget)
                    } else {
                        cpu.run_slice(&mut engine, &mut b, budget)
                    };
                    let expected = if let Some(view) = &mut va {
                        reference.run_parallel(&mut re, view, budget)
                    } else {
                        reference.run_slice(&mut a, budget)
                    };
                    assert_eq!(
                        format!("{actual:?}"),
                        format!("{expected:?}"),
                        "{replacement:x}; {mode}; {budget}"
                    );
                    assert_eq!(cpu.architectural_state(), reference.architectural_state());
                    assert_eq!(cpu.fault_retired(), reference.fault_retired());
                    if !matches!(actual, SliceOutcome::Yield { .. }) {
                        break;
                    }
                }
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0);
                }
                for (i, original) in words.into_iter().enumerate() {
                    let got = if let Some(view) = &vb {
                        view.fetch_u32(0x1000 + i as u64 * 4).unwrap()
                    } else {
                        b.fetch_u32(0x1000 + i as u64 * 4).unwrap()
                    };
                    assert_eq!(got, if i == 3 { replacement } else { original });
                }
            }
        }
    }
}
