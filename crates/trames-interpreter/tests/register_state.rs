// SPDX-License-Identifier: GPL-3.0-or-later
use trames_interpreter::{Cpu, SliceOutcome};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

#[test]
fn register_31_distinguishes_zero_stack_and_vector_state_across_slices() {
    let words: [u32; 17] = [
        0x3dc0089f, // ldr q31, [x4, #32]: nonzero initial SIMD state
        0xd2800120, // mov x0, #9
        0xd28000a1, // mov x1, #5
        0x91001c1f, // add sp, x0, #7
        0xaa0103ff, // mov xzr, x1
        0xeb01001f, // subs xzr, x0, x1
        0x91000fe2, // add x2, sp, #3
        0xaa1f03e3, // orr x3, xzr, xzr
        0xd29fffff, // movz xzr, #0xffff
        0x1000001f, // adr xzr, .
        0xf900009f, // str xzr, [x4]
        0xf940009f, // ldr xzr, [x4]
        0xa940149f, // ldp xzr, x5, [x4]
        0x9a9f03e6, // csel x6, xzr, xzr, eq
        0x3dc0009f, // ldr q31, [x4]
        0x3d80049f, // str q31, [x4, #16]: observe SIMD state through memory
        0xd4000001, // svc #0
    ];
    for budget in [1, 2, 3, 7, 64] {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.iter().enumerate() {
            memory
                .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        let mut cpu = Cpu::new(0x1000, 0x1234);
        // The second run uses warmed decoded operands and starts with nonzero
        // scalar/vector destinations. Every slice boundary must publish state.
        for _ in 0..2 {
            cpu.pc = 0x1000;
            cpu.sp = 0x1234;
            cpu.set_x(4, 0x2000);
            cpu.set_x(3, u64::MAX);
            cpu.set_x(6, u64::MAX);
            cpu.set_x(31, u64::MAX);
            memory.write_array(0x2010, u128::MAX.to_le_bytes()).unwrap();
            memory.write_array(0x2020, u128::MAX.to_le_bytes()).unwrap();
            memory
                .write_array(0x2000, (7u128 | (64u128 << 64)).to_le_bytes())
                .unwrap();
            let mut retired = 0;
            loop {
                match cpu.run_slice(&mut memory, budget) {
                    SliceOutcome::Yield { instructions } => retired += instructions,
                    SliceOutcome::Syscall { instructions } => {
                        retired += instructions;
                        break;
                    }
                    outcome => panic!("unexpected result: {outcome:?}"),
                }
                assert!(retired < words.len() as u64);
                assert_eq!(cpu.x(31), 0);
            }
            assert_eq!(retired, words.len() as u64);
            assert_eq!(cpu.pc, 0x1000 + words.len() as u64 * 4);
            assert_eq!(
                (cpu.sp, cpu.x(2), cpu.x(3), cpu.x(5), cpu.x(6)),
                (16, 19, 0, 64, 0)
            );
            assert_eq!(cpu.x(31), 0);
            assert_eq!(
                u128::from_le_bytes(memory.read_array::<16>(0x2010).unwrap()),
                64u128 << 64
            );
            assert_eq!(cpu.nzcv(), 2);
            assert_eq!(memory.read_array::<8>(0x2000).unwrap(), [0; 8]);
            assert_eq!(cpu.clone().x(31), 0);
        }
    }
}

#[test]
fn public_register_access_keeps_bounds_checks() {
    let mut cpu = Cpu::default();
    for index in [32, usize::MAX] {
        assert!(std::panic::catch_unwind(|| cpu.x(index)).is_err());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cpu.set_x(index, 7))).is_err()
        );
    }
    assert_eq!(cpu.x(31), 0);
}
