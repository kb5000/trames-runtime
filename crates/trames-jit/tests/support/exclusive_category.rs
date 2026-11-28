// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn forms() -> Vec<(u32, u32, usize)> {
    let mut forms = Vec::new();
    for pair in [false, true] {
        for size in if pair { 2..4 } else { 0..4 } {
            for acquire in [false, true] {
                for release in [false, true] {
                    let lr = if pair { 0x887f0000 } else { 0x085f7c00 };
                    let sc = if pair { 0x88200000 } else { 0x08007c00 };
                    let width = if pair { 2 << size } else { 1 << size };
                    let size_bits = if pair { (size - 2) << 30 } else { size << 30 };
                    forms.push((
                        lr | size_bits | (u32::from(acquire) << 15),
                        sc | size_bits | (u32::from(release) << 15),
                        width,
                    ));
                }
            }
        }
    }
    forms
}
fn run(cpu: &mut Cpu, engine: &mut Engine, memory: &mut impl CpuMemory, budget: u64) -> u64 {
    let mut retired = 0;
    for _ in 0..32 {
        match cpu.run_slice(engine, memory, budget) {
            SliceOutcome::Yield { instructions } => retired += instructions,
            SliceOutcome::Syscall { instructions } => return retired + instructions,
            other => panic!("unexpected {other:?} at {:x}", cpu.pc()),
        }
    }
    panic!("exclusive sequence did not terminate");
}

#[test]
fn entire_exclusive_category_preserves_all_state_bytes_and_slice_budgets() {
    // Real SC is allowed to fail spuriously. Compare the complete state to the
    // same architectural reference outcome (clear its reservation on failure).
    for (lr, sc, width) in forms() {
        let pair = lr & (1 << 21) != 0;
        for base in [1, 31] {
            for budget in [1, 2, 3, 4, 64] {
                for mode in 0..3 {
                    // serial, guarded worker, private epoch
                    let lr = lr | (base << 5) | if pair { 2 << 10 } else { 0 };
                    let sc = sc | (3 << 16) | (base << 5) | 4 | if pair { 5 << 10 } else { 0 };
                    let words = [lr, 0x9a0800e6, sc, 0xd4000001]; // adc x6,x7,x8
                    let mut state = initial();
                    state.registers[1] = 0x10000;
                    state.sp = 0x10000;
                    state.registers[3] = 0xfeed;
                    let mut actual = Cpu::new(0, 0);
                    actual.restore_architectural_state(&state);
                    let mut m = memory(&words);
                    m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
                    let original = [0x95; 32];
                    m.write(0x10000, &original).unwrap();
                    let mut registry = trames_memory::parallel::Registry::default();
                    let mut view = (mode != 0).then(|| m.parallel_view(&mut registry).unwrap());
                    if mode == 2 {
                        assert!(unsafe {
                            trames_memory::parallel::View::try_private_epoch(&mut [view
                                .as_mut()
                                .unwrap()])
                        });
                    }
                    let mut engine = Engine::default();
                    let retired = if let Some(view) = &mut view {
                        run(&mut actual, &mut engine, view, budget)
                    } else {
                        run(&mut actual, &mut engine, &mut m, budget)
                    };
                    assert_eq!(retired, 4, "{lr:08x}/{sc:08x} budget={budget}");
                    assert!(actual.x(3) <= 1);
                    let mut reference = trames_interpreter::Cpu::new(0, 0);
                    reference.restore_architectural_state(&state);
                    let mut expected = memory(&words);
                    expected
                        .map(0x10000, hardware_span(), Permissions::RW)
                        .unwrap();
                    expected.write(0x10000, &original).unwrap();
                    reference.run_slice(&mut expected, 2);
                    if actual.x(3) != 0 {
                        reference.clear_exclusive();
                    }
                    reference.run_slice(&mut expected, 64);
                    assert_eq!(
                        actual.architectural_state(),
                        reference.architectural_state(),
                        "{lr:08x}/{sc:08x} mode={mode} budget={budget}"
                    );
                    let mut bytes = [0; 32];
                    if let Some(view) = &view {
                        view.read(0x10000, &mut bytes).unwrap();
                    } else {
                        m.read(0x10000, &mut bytes).unwrap();
                    }
                    assert_eq!(
                        bytes,
                        expected.read_array::<32>(0x10000).unwrap(),
                        "width={width}"
                    );
                    if NATIVE_COMPILED {
                        assert_eq!(engine.stats.fallback_instructions, 0);
                        if mode != 1 && budget >= 3 {
                            assert!(engine.memory_stats().exclusive_windows > 0);
                        }
                        if mode == 1 {
                            assert_eq!(engine.memory_stats().exclusive_windows, 0);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn clrex_entire_option_category_clears_existing_monitor_without_interpreter() {
    for option in 0..16 {
        let words = [
            0xc85ffc20,
            0xd503305f | (option << 8),
            0xc803fc24,
            0xd4000001,
        ];
        for parallel in [false, true] {
            let mut state = initial();
            state.registers[1] = 0x10000;
            let engine = compare_memory_sequence(&words, &state, 64, parallel);
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn exclusive_monitor_survives_helpers_and_task_migration_but_rejects_aba() {
    // LR, unrelated native helper store, SC, SVC. Distinct granules preserve the
    // reservation. ABA/same-value writes in the reserved granule invalidate it.
    let words = [0xc85ffc20, 0xf9000044, 0xc803fc24, 0xd4000001];
    for aba in [false, true] {
        let mut m = memory(&words);
        m.write_array(0x2000, 17u64.to_le_bytes()).unwrap();
        let mut registry = trames_memory::parallel::Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        let mut writer = view.clone();
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(1, 0x2000);
        cpu.set_x(2, 0x2040);
        cpu.set_x(4, 99);
        let mut first = Engine::default();
        assert_eq!(
            outcome(&cpu.run_parallel(&mut first, &mut view, 1)),
            ("yield", 1)
        );
        if aba {
            writer.write_array(0x2000, 18u64.to_le_bytes()).unwrap();
            writer.write_array(0x2000, 17u64.to_le_bytes()).unwrap();
        } else {
            writer.write_array(0x2080, [7; 8]).unwrap();
        }
        let (cpu, last) = std::thread::spawn(move || {
            let mut last = Engine::default();
            assert_eq!(
                outcome(&cpu.run_parallel(&mut last, &mut view, 64)),
                ("syscall", 3)
            );
            (cpu, last.stats.fallback_instructions)
        })
        .join()
        .unwrap();
        assert!(cpu.x(3) <= 1);
        if aba {
            assert_eq!(cpu.x(3), 1);
        }
        assert_eq!(
            writer.read_u64(0x2000).unwrap(),
            if cpu.x(3) == 0 { 99 } else { 17 }
        );
        assert_eq!(writer.read_u64(0x2040).unwrap(), 99);
        if NATIVE_COMPILED {
            assert_eq!((first.stats.fallback_instructions, last), (0, 0));
        }
    }
}

#[test]
fn exclusive_faults_have_precise_pc_retirement_and_no_status_writeback() {
    for (lr, sc, width) in forms() {
        let pair = lr & (1 << 21) != 0;
        let lr = lr | (1 << 5) | if pair { 2 << 10 } else { 0 };
        let sc = sc | (3 << 16) | (1 << 5) | 4 | if pair { 5 << 10 } else { 0 };
        for address in [0x10000, 0x10001, 0x18000] {
            for read_only in [false, true] {
                let words = [0xd2800249, lr, 0xb10004c6, sc, 0xd4000001]; // dirty prefixes
                let mut a = memory(&words);
                let mut b = memory(&words);
                for m in [&mut a, &mut b] {
                    m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
                    m.write(0x10000, &[0x66; 32]).unwrap();
                    if read_only {
                        m.protect(0x10000, hardware_span(), Permissions::R).unwrap();
                    }
                }
                let mut state = initial();
                state.registers[1] = address;
                state.registers[3] = 0xfeed;
                let mut expected = trames_interpreter::Cpu::new(0, 0);
                let mut actual = Cpu::new(0, 0);
                expected.restore_architectural_state(&state);
                actual.restore_architectural_state(&state);
                let mut engine = Engine::default();
                let x = expected.run_slice(&mut a, 64);
                let y = actual.run_slice(&mut engine, &mut b, 64);
                if matches!(x, SliceOutcome::Fault(_)) {
                    assert_eq!(
                        format!("{x:?}"),
                        format!("{y:?}"),
                        "width={width} address={address:x}"
                    );
                    assert_eq!(actual.architectural_state(), expected.architectural_state());
                    assert_eq!(actual.fault_retired(), expected.fault_retired());
                    assert_eq!(actual.x(3), 0xfeed);
                } else {
                    assert_eq!(outcome(&y), ("syscall", 5));
                    assert!(actual.x(3) <= 1);
                }
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0);
                }
            }
        }
    }
}

#[test]
fn exclusive_zero_registers_aliases_pressure_and_unmatched_stores_remain_native() {
    for words in [
        vec![0xc85f7c3f, 0xc8037c3f, 0xd4000001], // XZR value load/store
        vec![0xc87f7c22, 0xc8237c3f, 0xd4000001], // pair includes zero value
        vec![0xc85f7c20, 0xc81f7c24, 0xd4000001], // discard SC status
        vec![0xc8037c24, 0xd4000001],             // no prior LR -> no memory access
        vec![0xc85f7c21, 0xc8037c24, 0xd4000001], // load aliases address
    ] {
        let mut m = memory(&words);
        m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
        m.write(0x10000, &[0; 32]).unwrap();
        let mut c = Cpu::new(0x1000, 0);
        c.set_x(1, 0x10000);
        c.set_x(4, 99);
        let mut e = Engine::default();
        assert_eq!(run(&mut c, &mut e, &mut m, 64), words.len() as u64);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0, "{words:x?}");
        }
    }
    // Too many live bindings must split to checked native exclusive accesses,
    // rather than emitting a frame spill between hardware LR and SC.
    let mut words = vec![0xc85ffc20];
    for reg in 7..20 {
        words.push(0x91000400 | (reg << 5) | reg);
    }
    words.extend_from_slice(&[0xc803fc24, 0xd4000001]);
    let mut m = memory(&words);
    m.write_array(0x2000, 4u64.to_le_bytes()).unwrap();
    let mut c = Cpu::new(0x1000, 0);
    c.set_x(1, 0x2000);
    let mut e = Engine::default();
    assert_eq!(run(&mut c, &mut e, &mut m, 64), words.len() as u64);
    if NATIVE_COMPILED {
        assert_eq!(e.stats.fallback_instructions, 0);
        assert_eq!(e.memory_stats().exclusive_windows, 0);
    }
}

#[test]
fn promoted_serial_pages_and_warm_cache_budget_cuts_reenter_hardware_windows() {
    let words = [0xc85ffc20, 0x91000400, 0xc803fc20, 0xb5ffffa3, 0xd4000001];
    let mut m = memory(&words);
    m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
    m.write_array(0x10000, 10u64.to_le_bytes()).unwrap();
    let mut c = Cpu::new(0x1000, 0);
    c.set_x(1, 0x10000);
    let mut e = Engine::default();
    // First single-stepping LR promotes bytes to the existing shared-page
    // reservation representation. Its unique owner must remain native-admitted.
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 1)), ("yield", 1));
    assert_eq!(run(&mut c, &mut e, &mut m, 64) % 4, 0);
    c.set_pc(0x1000);
    assert!(run(&mut c, &mut e, &mut m, 64) >= 5);
    let windows = e.memory_stats().exclusive_windows;
    if NATIVE_COMPILED {
        assert!(windows > 0);
    }
    c.set_pc(0x1000);
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 1)), ("yield", 1));
    assert_eq!(c.pc(), 0x1004);
    assert_eq!(e.memory_stats().exclusive_windows, windows);
    assert!(run(&mut c, &mut e, &mut m, 2) >= 4);
    assert_eq!(m.read_u64(0x10000).unwrap(), 13);
    if NATIVE_COMPILED {
        assert_eq!(e.stats.fallback_instructions, 0);
    }
}

#[test]
fn shared_exclusive_retry_loops_preserve_updates_without_a_new_algorithm_lock() {
    let words = [0xc85ffc20, 0x91000400, 0xc803fc20, 0xb5ffffa3, 0xd4000001];
    let mut m = memory(&words);
    let mut registry = trames_memory::parallel::Registry::default();
    let views: Vec<_> = (0..4)
        .map(|_| m.parallel_view(&mut registry).unwrap())
        .collect();
    let workers: Vec<_> = views
        .into_iter()
        .map(|mut view| {
            std::thread::spawn(move || {
                let mut e = Engine::default();
                let mut c = Cpu::new(0x1000, 0);
                c.set_x(1, 0x2000);
                for _ in 0..200 {
                    c.set_pc(0x1000);
                    loop {
                        match c.run_parallel(&mut e, &mut view, 4096) {
                            SliceOutcome::Syscall { .. } => break,
                            SliceOutcome::Yield { .. } => {}
                            other => panic!("{other:?}"),
                        }
                    }
                }
                if NATIVE_COMPILED {
                    assert_eq!(e.stats.fallback_instructions, 0);
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    m.commit_parallel().unwrap();
    assert_eq!(m.read_u64(0x2000).unwrap(), 800);
}

#[test]
fn independent_llvm_exclusive_encodings_keep_all_register_aliases_native() {
    let words: Vec<_> =
        include_str!("../../../../docs/validation/jit-exclusive-20261128/category.words")
            .lines()
            .map(|line| u32::from_str_radix(line, 16).unwrap())
            .collect();
    assert_eq!(words.len(), 400);
    for pair in words[..384].chunks_exact(2) {
        for budget in [1, 64] {
            let mut m = memory(&[pair[0], pair[1], 0xd4000001]);
            m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
            m.write(0x10000, &[0x55; 32]).unwrap();
            let mut c = Cpu::new(0x1000, 0x10000);
            c.set_x(1, 0x10000);
            let mut e = Engine::default();
            assert_eq!(run(&mut c, &mut e, &mut m, budget), 3);
            assert!(c.x(3) <= 1);
            let element = 1usize << (pair[0] >> 30);
            let mut expected = [0x55; 32];
            if c.x(3) == 0 {
                if pair[0] & 31 == 31 {
                    expected[..element].fill(0);
                }
                if pair[0] & (1 << 21) != 0 && (pair[0] >> 10) & 31 == 31 {
                    expected[element..2 * element].fill(0);
                }
            }
            assert_eq!(m.read_array::<32>(0x10000).unwrap(), expected);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0, "{pair:x?}");
            }
        }
    }
}

#[test]
fn closed_window_misalignment_uses_hardware_recovery_and_original_fault_boundary() {
    for (lr, sc, width) in forms() {
        if width == 1 {
            continue;
        }
        let pair = lr & (1 << 21) != 0;
        let lr = lr | (1 << 5) | if pair { 2 << 10 } else { 0 };
        let sc = sc | (3 << 16) | (1 << 5) | 4 | if pair { 5 << 10 } else { 0 };
        let mut state = initial();
        state.registers[1] = 0x10001;
        for parallel in [false, true] {
            let e =
                compare_memory_sequence(&[lr, 0xba0800e6, sc, 0xd4000001], &state, 64, parallel);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
            }
        }
    }
}

#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
#[test]
fn revoked_exclusive_aliases_rejoin_checked_faults_with_exact_prefix_and_monitor() {
    use trames_memory::{Access, InstructionEpochs, MemoryError, NativePage};
    struct Revoked {
        memory: Memory,
        alias: usize,
        load: bool,
    }
    impl Revoked {
        fn restore(&mut self) {
            if self.alias != 0 {
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            self.alias as *mut _,
                            4096,
                            libc::PROT_READ | libc::PROT_WRITE,
                        )
                    },
                    0
                );
            }
        }
    }
    impl CpuMemory for Revoked {
        fn cpu_native_available(&self) -> bool {
            self.memory.cpu_native_available()
        }
        fn cpu_hardware_ordering(&self) -> bool {
            true
        }
        unsafe fn cpu_exclusive_page(&mut self, address: u64, len: usize) -> Option<NativePage> {
            let page = unsafe { self.memory.cpu_exclusive_page(address, len) }?;
            self.alias = page.read;
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        page.read as *mut _,
                        4096,
                        if self.load {
                            libc::PROT_NONE
                        } else {
                            libc::PROT_READ
                        },
                    )
                },
                0
            );
            Some(page)
        }
        fn exclusive_read(&mut self, a: u64, out: &mut [u8]) -> Result<u128, MemoryError> {
            self.restore();
            if self.load {
                return Err(MemoryError::Permission {
                    address: a,
                    access: Access::Read,
                });
            }
            self.memory.exclusive_read(a, out)
        }
        fn exclusive_write(
            &mut self,
            a: u64,
            bytes: &[u8],
            token: Option<u128>,
        ) -> Result<bool, MemoryError> {
            self.restore();
            if !self.load {
                return Err(MemoryError::Permission {
                    address: a,
                    access: Access::Write,
                });
            }
            self.memory.exclusive_write(a, bytes, token)
        }
        fn atomic_update<T>(
            &mut self,
            a: u64,
            n: usize,
            f: impl FnOnce(&mut [u8]) -> (T, bool),
        ) -> Result<T, MemoryError> {
            self.memory.atomic_update(a, n, f)
        }
        fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
            self.memory.instruction_epochs()
        }
        fn instruction_identity(&self) -> (u64, u64, u64) {
            self.memory.instruction_identity()
        }
        fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
            self.memory.instruction_page_identity(a)
        }
        fn mapped_at_or_after(&self, a: u64) -> bool {
            self.memory.mapped_at_or_after(a)
        }
        fn read(&self, a: u64, b: &mut [u8]) -> Result<(), MemoryError> {
            self.memory.read(a, b)
        }
        fn write(&mut self, a: u64, b: &[u8]) -> Result<(), MemoryError> {
            self.memory.write(a, b)
        }
        fn check(&self, a: u64, n: usize, x: Access) -> Result<(), MemoryError> {
            self.memory.check(a, n, x)
        }
        fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
            self.memory.check_translation(a)
        }
        fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
            self.memory.fetch_u32(a)
        }
    }
    for load in [true, false] {
        let words = [0xc85ffc20, 0xba0800e6, 0xc803fc24, 0xd4000001];
        let mut m = memory(&words);
        m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
        m.write_array(0x10000, 123u64.to_le_bytes()).unwrap();
        let mut reference_memory = memory(&words);
        reference_memory
            .map(0x10000, hardware_span(), Permissions::RW)
            .unwrap();
        reference_memory
            .write_array(0x10000, 123u64.to_le_bytes())
            .unwrap();
        reference_memory
            .protect(
                0x10000,
                hardware_span(),
                if load {
                    Permissions::NONE
                } else {
                    Permissions::R
                },
            )
            .unwrap();
        let mut initial = initial();
        initial.registers[1] = 0x10000;
        initial.registers[3] = 0xfeed;
        let mut c = Cpu::new(0, 0);
        c.restore_architectural_state(&initial);
        let mut r = trames_interpreter::Cpu::new(0, 0);
        r.restore_architectural_state(&initial);
        let mut revoked = Revoked {
            memory: m,
            alias: 0,
            load,
        };
        let mut e = Engine::default();
        let actual = c.run_slice(&mut e, &mut revoked, 64);
        let expected = r.run_slice(&mut reference_memory, 64);
        assert!(revoked.alias != 0);
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        assert_eq!(c.architectural_state(), r.architectural_state());
        assert_eq!(c.fault_retired(), r.fault_retired());
        assert_eq!(c.x(3), 0xfeed);
        assert_eq!(revoked.memory.read_u64(0x10000).unwrap(), 123);
        assert_eq!(e.stats.fallback_instructions, 0);
    }
}
