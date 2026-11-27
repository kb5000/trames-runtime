// SPDX-License-Identifier: GPL-3.0-or-later
//! Ordered operands use real canonical bytes whenever the host can address them.
use std::sync::atomic::{fence, Ordering};

#[repr(align(16))]
pub(crate) struct Operand(pub [u8; 8]);

pub(crate) fn valid(len: usize) -> bool {
    matches!(len, 1 | 2 | 4 | 8)
}

pub(crate) fn read<T>(bytes: &[u8], operation: impl FnOnce(&[u8]) -> T) -> (T, bool) {
    if (bytes.as_ptr() as usize).is_multiple_of(bytes.len()) {
        return (operation(bytes), true);
    }
    let mut aligned = Operand([0; 8]);
    aligned.0[..bytes.len()].copy_from_slice(bytes);
    // Only an unrepresentable provider pointer needs canonical copy + acquire.
    // LDAR on its own temporary would not order the actual preceding read.
    fence(Ordering::Acquire);
    (operation(&aligned.0[..bytes.len()]), false)
}
pub(crate) fn write<T>(bytes: &mut [u8], operation: impl FnOnce(&mut [u8]) -> T) -> (T, bool) {
    if (bytes.as_ptr() as usize).is_multiple_of(bytes.len()) {
        return (operation(bytes), true);
    }
    let mut aligned = Operand([0; 8]);
    let value = operation(&mut aligned.0[..bytes.len()]);
    // Release belongs before publication to the real destination, not merely
    // before a store into staging. Ordinary RAM never takes this branch.
    fence(Ordering::Release);
    bytes.copy_from_slice(&aligned.0[..bytes.len()]);
    (value, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_operands_borrow_aligned_bytes_and_stage_incongruent_providers() {
        for len in [1, 2, 4, 8] {
            let mut operand = Operand([0x83; 8]);
            let canonical = operand.0.as_ptr() as usize;
            let (pointer, direct) = read(&operand.0[..len], |s| s.as_ptr() as usize);
            assert_eq!((pointer, direct), (canonical, true));
            let (_, direct) = write(&mut operand.0[..len], |s| {
                assert_eq!(s.as_ptr() as usize, canonical);
                s.fill(0x42);
            });
            assert!(direct);
            assert_eq!(&operand.0[..len], &vec![0x42; len]);
        }
        #[repr(align(16))]
        struct Provider([u8; 16]);
        for len in [2, 4, 8] {
            let mut provider = Provider([0x81; 16]);
            let (_, direct) = read(&provider.0[1..1 + len], |s| {
                assert_eq!(s.as_ptr() as usize % len, 0);
                assert_eq!(s, &vec![0x81; len]);
            });
            assert!(!direct);
            let (_, direct) = write(&mut provider.0[1..1 + len], |s| {
                assert_eq!(s.as_ptr() as usize % len, 0);
                s.fill(0x43);
            });
            assert!(!direct);
            assert_eq!(&provider.0[1..1 + len], &vec![0x43; len]);
            assert_eq!(provider.0[0], 0x81);
            assert_eq!(provider.0[1 + len], 0x81);
        }
    }
}
