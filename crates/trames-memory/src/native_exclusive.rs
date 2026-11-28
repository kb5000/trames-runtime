// SPDX-License-Identifier: GPL-3.0-or-later
//! Alignment transport at the existing exclusive byte boundary. Ordinary
//! aligned canonical operands gain no fence or software atomic algorithm.
use std::sync::atomic::{fence, Ordering};
#[repr(align(16))]
pub(crate) struct Operand(pub [u8; 16]);
pub(crate) fn read<T>(
    bytes: &[u8],
    acquire: bool,
    operation: impl FnOnce(&[u8]) -> T,
) -> (T, bool) {
    if (bytes.as_ptr() as usize).is_multiple_of(bytes.len()) {
        return (operation(bytes), true);
    }
    let mut aligned = Operand([0; 16]);
    aligned.0[..bytes.len()].copy_from_slice(bytes);
    if acquire {
        fence(Ordering::Acquire);
    }
    (operation(&aligned.0[..bytes.len()]), false)
}
pub(crate) fn write(
    bytes: &mut [u8],
    release: bool,
    operation: impl FnOnce(&mut [u8]) -> bool,
) -> (bool, bool) {
    if (bytes.as_ptr() as usize).is_multiple_of(bytes.len()) {
        return (operation(bytes), true);
    }
    let mut aligned = Operand([0; 16]);
    let written = operation(&mut aligned.0[..bytes.len()]);
    if written {
        if release {
            fence(Ordering::Release);
        }
        bytes.copy_from_slice(&aligned.0[..bytes.len()]);
    }
    (written, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unaligned_transport_preserves_width_and_never_publishes_a_failed_store() {
        for len in [2, 4, 8, 16] {
            #[repr(align(16))]
            struct Buffer([u8; 48]);
            let mut bytes = Buffer([0x77; 48]);
            let (value, direct) = read(&bytes.0[1..1 + len], true, |b| {
                assert!((b.as_ptr() as usize).is_multiple_of(len));
                b.to_vec()
            });
            assert!(!direct);
            assert_eq!(value, vec![0x77; len]);
            let (written, direct) = write(&mut bytes.0[1..1 + len], true, |b| {
                assert!((b.as_ptr() as usize).is_multiple_of(len));
                b.fill(0x88);
                false
            });
            assert!(!written && !direct);
            assert_eq!(bytes.0, [0x77; 48]);
            assert_eq!(
                write(&mut bytes.0[1..1 + len], true, |b| {
                    b.fill(0x99);
                    true
                }),
                (true, false)
            );
            assert_eq!(&bytes.0[1..1 + len], vec![0x99; len]);
            assert_eq!(bytes.0[0], 0x77);
            assert_eq!(bytes.0[1 + len], 0x77);
        }
    }
    #[test]
    fn callback_failure_preserves_the_existing_memory_monitor_and_canonical_bytes() {
        use crate::{CpuMemory, Memory, Permissions};
        for parallel in [false, true] {
            let mut m = Memory::default();
            m.map(0x10000, 16384, Permissions::RW).unwrap();
            m.write(0x10000, &[0x55; 16]).unwrap();
            fn check(memory: &mut impl CpuMemory) {
                let (old, token, _) = memory
                    .cpu_exclusive_read(0x10000, 16, true, |b| b.to_vec())
                    .unwrap();
                assert_eq!(old, vec![0x55; 16]);
                let before = memory.instruction_identity();
                assert!(
                    !memory
                        .cpu_exclusive_write(0x10000, 16, Some(token), true, |_| false)
                        .unwrap()
                        .0
                );
                assert_eq!(memory.instruction_identity(), before);
                assert_eq!(memory.read_array::<16>(0x10000).unwrap(), [0x55; 16]);
                assert!(memory
                    .exclusive_write(0x10000, &[0x66; 16], Some(token))
                    .unwrap());
                let (_, token, _) = memory
                    .cpu_exclusive_read(0x10000, 16, false, |_| ())
                    .unwrap();
                memory.write(0x10000, &[0x66; 16]).unwrap();
                assert!(
                    !memory
                        .cpu_exclusive_write(0x10000, 16, Some(token), false, |_| panic!(
                            "invalidated token cannot execute native SC"
                        ))
                        .unwrap()
                        .0
                );
            }
            if parallel {
                check(&mut m.parallel_view(&mut Default::default()).unwrap());
            } else {
                check(&mut m);
            }
        }
    }
}
