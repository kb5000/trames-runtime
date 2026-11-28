// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::cell::{Cell, RefCell};
use std::sync::atomic::Ordering;
use trames_memory::{Access, InstructionEpochs, MemoryError};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Read(u64, usize),
    Write(u64, Vec<u8>),
    Check(u64, usize, Access),
    Atomic(u64, usize),
    Published(bool, Vec<u8>),
    Fence(Ordering),
    ExclusiveRead(u64, usize),
    ExclusiveWrite(u64, Vec<u8>, bool),
}
struct Abstract {
    memory: Memory,
    events: RefCell<Vec<Event>>,
    epochs: bool,
    exports: Cell<u64>,
    #[cfg(feature = "native-aarch64")]
    aliases: bool,
}
impl Abstract {
    fn new(memory: Memory, mode: usize) -> Self {
        Self {
            memory,
            events: RefCell::new(Vec::new()),
            epochs: mode != 0,
            exports: Cell::new(0),
            #[cfg(feature = "native-aarch64")]
            aliases: mode == 2,
        }
    }
}
impl CpuMemory for Abstract {
    fn mapped_at_or_after(&self, a: u64) -> bool {
        self.memory.mapped_at_or_after(a)
    }
    fn read(&self, a: u64, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.events.borrow_mut().push(Event::Read(a, bytes.len()));
        self.memory.read(a, bytes)
    }
    fn write(&mut self, a: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.events
            .borrow_mut()
            .push(Event::Write(a, bytes.to_vec()));
        self.memory.write(a, bytes)
    }
    fn check(&self, a: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.events.borrow_mut().push(Event::Check(a, len, access));
        self.memory.check(a, len, access)
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
    fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
        if self.epochs {
            self.memory.instruction_epochs()
        } else {
            None
        }
    }
    fn atomic_update<T>(
        &mut self,
        a: u64,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        self.events.borrow_mut().push(Event::Atomic(a, len));
        let events = &self.events;
        CpuMemory::atomic_update(&mut self.memory, a, len, |bytes| {
            let result = f(bytes);
            events
                .borrow_mut()
                .push(Event::Published(result.1, bytes.to_vec()));
            result
        })
    }
    fn exclusive_read(&mut self, a: u64, bytes: &mut [u8]) -> Result<u128, MemoryError> {
        self.events
            .borrow_mut()
            .push(Event::ExclusiveRead(a, bytes.len()));
        CpuMemory::exclusive_read(&mut self.memory, a, bytes)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        bytes: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        let written = CpuMemory::exclusive_write(&mut self.memory, a, bytes, token)?;
        self.events
            .borrow_mut()
            .push(Event::ExclusiveWrite(a, bytes.to_vec(), written));
        Ok(written)
    }
    fn fence(&self, order: Ordering) {
        self.events.borrow_mut().push(Event::Fence(order));
        CpuMemory::fence(&self.memory, order);
    }
    #[cfg(feature = "native-aarch64")]
    fn cpu_native_available(&self) -> bool {
        self.aliases && self.memory.cpu_native_available()
    }
    #[cfg(feature = "native-aarch64")]
    unsafe fn cpu_native_page(&mut self, a: u64, write: bool) -> Option<trames_memory::NativePage> {
        self.exports.set(self.exports.get() + 1);
        unsafe { self.memory.cpu_native_page(a, write) }
    }
}

fn cases() -> Vec<(u32, &'static str, i64)> {
    let words =
        include_str!("../../../../docs/validation/jit-abstract-memory-20261128/category.words");
    let cases =
        include_str!("../../../../docs/validation/jit-abstract-memory-20261128/category.cases");
    words
        .lines()
        .zip(cases.lines())
        .map(|(word, case)| {
            let mut fields = case.split_whitespace();
            (
                u32::from_str_radix(word, 16).unwrap(),
                fields.next().unwrap(),
                fields.next().unwrap().parse().unwrap(),
            )
        })
        .collect()
}
fn available(word: u32, name: &str) -> bool {
    let host = <Cpu as Backend>::features();
    match name {
        "ldlar" | "stllr" => {
            #[cfg(all(
                target_arch = "aarch64",
                any(target_os = "linux", target_os = "android")
            ))]
            {
                if unsafe { libc::getauxval(libc::AT_HWCAP) } & (1 << 11) != 0 {
                    let id: u64;
                    unsafe {
                        std::arch::asm!("mrs {}, id_aa64mmfr1_el1", out(reg) id, options(nomem, nostack, preserves_flags));
                    }
                    return (id >> 16) & 15 == 1;
                }
            }
            false
        }
        "ldapr" => host.hwcap & (1 << 15) != 0,
        "ldapur" | "stlur" => host.hwcap & (1 << 26) != 0,
        "swpp" | "ldclrp" | "ldsetp" => host.hwcap2 & (1 << 47) != 0,
        "ldar" | "stlr" => true,
        _ => {
            let _ = word;
            host.hwcap & (1 << 8) != 0
        }
    }
}
fn state_for(word: u32, name: &str, offset: i64, matched: bool, unaligned: bool) -> Aarch64State {
    let mut state = initial();
    let rn = ((word >> 5) & 31) as usize;
    if name == "cas" || name == "casp" {
        let compare = ((word >> 16) & 31) as usize;
        let size = if name == "cas" {
            1 << (word >> 30)
        } else {
            4 << (word >> 30)
        };
        let mask = if size == 8 {
            u64::MAX
        } else {
            (1 << (size * 8)) - 1
        };
        if compare != 31 {
            state.registers[compare] = 0xa5a5_a5a5_a5a5_a5a5 & mask ^ u64::from(!matched);
        }
        if name == "casp" && compare + 1 != 31 {
            state.registers[compare + 1] = 0xa5a5_a5a5_a5a5_a5a5 & mask;
        }
    }
    let address = (0xab00_0000_0001_0100u64 + u64::from(unaligned)).wrapping_sub(offset as u64);
    if rn == 31 {
        state.sp = address;
    } else {
        state.registers[rn] = address;
    }
    state
}
fn populated(words: &[u32]) -> Memory {
    let mut m = memory(words);
    m.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write(0x10000, &vec![0xa5; PAGE_SIZE as usize]).unwrap();
    m
}
fn compare(
    word: u32,
    name: &str,
    offset: i64,
    mode: usize,
    budget: u64,
    fault: usize,
    matched: bool,
) -> Engine {
    let words = [0xb1000529, 0x1e622820, word, word, 0xd4000001];
    let prepare = || {
        let mut m = populated(&words);
        match fault {
            1 => m
                .protect(
                    0x10000,
                    PAGE_SIZE,
                    Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                )
                .unwrap(),
            2 => m
                .protect(
                    0x10000,
                    PAGE_SIZE,
                    Permissions {
                        read: false,
                        write: true,
                        execute: false,
                    },
                )
                .unwrap(),
            3 => m.unmap(0x10000, PAGE_SIZE).unwrap(),
            _ => (),
        }
        Abstract::new(m, mode)
    };
    let mut a = prepare();
    let mut b = prepare();
    let state = state_for(word, name, offset, matched, fault == 4);
    let mut actual = Cpu::new(0, 0);
    let mut reference = trames_interpreter::Cpu::new(0, 0);
    actual.restore_architectural_state(&state);
    reference.restore_architectural_state(&state);
    let mut engine = Engine::default();
    let mut finished = false;
    for _ in 0..8 {
        let actual_exit = actual.run_slice(&mut engine, &mut a, budget);
        let expected_exit = reference.run_slice(&mut b, budget);
        assert_eq!(
            format!("{actual_exit:?}"),
            format!("{expected_exit:?}"),
            "{word:x}/{mode}/{budget}/{fault}"
        );
        assert_eq!(
            actual.architectural_state(),
            reference.architectural_state(),
            "{word:x}"
        );
        assert_eq!(
            actual.fault_retired(),
            reference.fault_retired(),
            "{word:x}"
        );
        assert_eq!(
            *a.events.borrow(),
            *b.events.borrow(),
            "{word:x}/{mode}/{budget}/{fault}"
        );
        if fault == 0 || fault == 4 {
            assert_eq!(
                a.memory.read_array::<4096>(0x10000).unwrap(),
                b.memory.read_array::<4096>(0x10000).unwrap()
            );
        }
        if !matches!(actual_exit, SliceOutcome::Yield { .. }) {
            finished = true;
            break;
        }
    }
    assert!(finished, "{word:x}");
    if fault == 1 || fault == 2 {
        a.memory
            .protect(0x10000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        b.memory
            .protect(0x10000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        assert_eq!(
            a.memory.read_array::<4096>(0x10000).unwrap(),
            b.memory.read_array::<4096>(0x10000).unwrap()
        );
    }
    assert_eq!(
        a.exports.get(),
        0,
        "abstract ordered/atomic operation bypassed its provider"
    );
    assert_eq!(engine.stats.fallback_instructions, 0, "{word:x}");
    for (i, word) in words.iter().enumerate() {
        assert_eq!(a.memory.fetch_u32(0x1000 + 4 * i as u64).unwrap(), *word);
    }
    engine
}

#[test]
fn all_llvm_abstract_ordered_and_atomic_forms_preserve_canonical_callbacks_without_fallback() {
    if !NATIVE_COMPILED {
        return;
    }
    let matrix = cases();
    assert_eq!(matrix.len(), 795);
    let mut admitted = 0;
    for (word, name, offset) in matrix {
        if !available(word, name) {
            continue;
        }
        admitted += 1;
        for mode in 0..3 {
            for budget in [1, 2, 3, 64] {
                for matched in [false, true] {
                    compare(word, name, offset, mode, budget, 0, matched);
                }
            }
        }
    }
    assert!(admitted >= 24, "baseline ordered forms must execute");
    eprintln!("abstract ordered/atomic: admitted {admitted}/795 encodings, {} whole-state/callback programs", admitted * 24);
}

#[test]
fn abstract_ordered_and_atomic_faults_keep_fence_and_publication_order() {
    if !NATIVE_COMPILED {
        return;
    }
    for (word, name, offset) in cases() {
        if !available(word, name) {
            continue;
        }
        for mode in 0..3 {
            for budget in [1, 3, 64] {
                for fault in 1..=4 {
                    compare(word, name, offset, mode, budget, fault, false);
                }
            }
        }
    }
}

#[test]
fn missing_host_extensions_fault_before_abstract_provider_data_callbacks() {
    if !NATIVE_COMPILED {
        return;
    }
    for (word, name, offset) in cases() {
        if available(word, name) {
            continue;
        }
        for mode in 0..3 {
            let mut memory = Abstract::new(populated(&[word, 0xd4000001]), mode);
            let state = state_for(word, name, offset, false, false);
            let mut cpu = Cpu::new(0, 0);
            cpu.restore_architectural_state(&state);
            let mut engine = Engine::default();
            assert!(
                matches!(cpu.run_slice(&mut engine,&mut memory,64),SliceOutcome::Fault(trames_engine::CpuFault::Instruction{pc:0x1000,instruction}) if instruction==word)
            );
            assert_eq!(cpu.architectural_state(), state);
            assert_eq!(cpu.fault_retired(), 0);
            assert!(memory.events.borrow().is_empty());
            assert_eq!(engine.stats.fallback_instructions, 0);
            assert_eq!(memory.exports.get(), 0);
        }
    }
}

#[test]
fn abstract_cas_publishes_only_successful_transactions_in_the_original_reservation_domain() {
    if !NATIVE_COMPILED || <Cpu as Backend>::features().hwcap & (1 << 8) == 0 {
        return;
    }
    let words = [0xc8e4fc20, 0xd4000001]; // casal x4,x0,[x1]
    for mode in 0..3 {
        for matched in [false, true] {
            let mut a = Abstract::new(populated(&words), mode);
            let mut b = Abstract::new(populated(&words), mode);
            let mut bytes = [0; 8];
            let at = a.exclusive_read(0x10100, &mut bytes).unwrap();
            let bt = b.exclusive_read(0x10100, &mut bytes).unwrap();
            let state = state_for(words[0], "cas", 0, matched, false);
            let mut c = Cpu::new(0, 0);
            let mut r = trames_interpreter::Cpu::new(0, 0);
            c.restore_architectural_state(&state);
            r.restore_architectural_state(&state);
            let mut e = Engine::default();
            assert_eq!(
                format!("{:?}", c.run_slice(&mut e, &mut a, 64)),
                format!("{:?}", r.run_slice(&mut b, 64))
            );
            let aw = a.exclusive_write(0x10100, &[0x3c; 8], Some(at)).unwrap();
            let bw = b.exclusive_write(0x10100, &[0x3c; 8], Some(bt)).unwrap();
            assert_eq!(aw, bw);
            assert_eq!(aw, !matched);
            assert_eq!(*a.events.borrow(), *b.events.borrow());
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}
